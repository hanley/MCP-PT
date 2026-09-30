"""Canvas capture and annotation tests. 

Reference data comes out of PT 9.0.0.0810: 'getWorkspaceImage("PNG")' returned the 
decimal bytes separated by comma and WITH SIGN, starting with '-119,80,78,71,13,10,26,10' 
— which is the PNG signature '89 50 4E 47 0D 0A 1A 0A'.
"""

from pathlib import Path

import pytest

from src.packet_tracer_mcp.domain.services.canvas import (
    IMAGE_FORMATS,
    CanvasImageError,
    decode_pt_image,
    normalize_format,
    parse_uuid_list,
    validate_color,
)

# Firma PNG tal como la manda PT: el 0x89 llega como -119.
PNG_HEAD = "-119,80,78,71,13,10,26,10"
JPG_HEAD = "-1,-40,-1"


class TestDecodePtImage:
    def test_signed_bytes_become_the_png_signature(self):
        """The initial 0x89 of a PNG arrives as -119 because the byte of Qt is signed."""
        blob = decode_pt_image(PNG_HEAD, "PNG")
        assert blob == bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])

    def test_jpg_signature(self):
        assert decode_pt_image(JPG_HEAD, "JPG") == bytes([0xFF, 0xD8, 0xFF])

    def test_unsigned_values_pass_through(self):
        """If PT ever sends 137 instead of -119, it's the same octet."""
        assert decode_pt_image("137,80,78,71,13,10,26,10", "PNG")[0] == 0x89

    def test_whitespace_and_trailing_comma_tolerated(self):
        assert decode_pt_image(" -119, 80,78, 71,13,10,26,10, ", "PNG")[:4] == b"\x89PNG"

    def test_empty_response_is_an_error(self):
        with pytest.raises(CanvasImageError):
            decode_pt_image("   ", "PNG")

    def test_non_numeric_is_an_error(self):
        with pytest.raises(CanvasImageError):
            decode_pt_image("-119,80,ERROR:algo,71", "PNG")

    def test_out_of_range_is_an_error(self):
        with pytest.raises(CanvasImageError):
            decode_pt_image("-119,80,999,71", "PNG")

    def test_wrong_magic_is_caught_before_writing_to_disk(self):
        """Writing a corrupt file and alerting when someone opens it is worse."""
        with pytest.raises(CanvasImageError, match="do not correspond"):
            decode_pt_image("1,2,3,4,5", "PNG")

    def test_decoded_bytes_are_writable_and_round_trip(self, tmp_path: Path):
        target = tmp_path / "cap.png"
        target.write_bytes(decode_pt_image(PNG_HEAD, "PNG"))
        assert target.read_bytes()[:4] == b"\x89PNG"


class TestNormalizeFormat:
    @pytest.mark.parametrize("raw", ["png", "PNG", " Png "])
    def test_case_and_spaces(self, raw):
        assert normalize_format(raw) == "PNG"

    def test_default_when_empty(self):
        assert normalize_format("") == "PNG"

    def test_unsupported_is_rejected(self):
        with pytest.raises(CanvasImageError):
            normalize_format("GIF")

    def test_every_declared_format_normalizes(self):
        for fmt in IMAGE_FORMATS:
            assert normalize_format(fmt) == fmt


class TestValidateColor:
    def test_valid_range(self):
        validate_color(0, 150, 255, 255)

    @pytest.mark.parametrize("bad", [(-1, 0, 0, 0), (0, 256, 0, 0), (0, 0, 0, 300)])
    def test_out_of_range_rejected(self, bad):
        with pytest.raises(ValueError):
            validate_color(*bad)


class TestParseUuidList:
    def test_none_is_empty(self):
        assert parse_uuid_list(None) == []

    def test_list_passes_through(self):
        assert parse_uuid_list(["{a}", "{b}"]) == ["{a}", "{b}"]

    def test_comma_string_is_split(self):
        assert parse_uuid_list("{a},{b}") == ["{a}", "{b}"]

    def test_blanks_dropped(self):
        assert parse_uuid_list("{a}, ,{b},") == ["{a}", "{b}"]


class TestCanvasTools:
    """Guards on the JS. They are closures in register_tools, so they are verified 
    by text just like TestReconcileWiring in test_live_reconcile.py."""

    def _src(self) -> str:
        return Path("src/packet_tracer_mcp/adapters/mcp/tool_registry.py").read_text(
            encoding="utf-8"
        )

    def test_no_draw_tool_is_shipped(self):
        """drawCircle/drawLine are not exposed: the third argument turned out to be the 
        Z-order, no radius or thickness, and colors are not applied as passed. 
        
        Measured in PT 9.0.0.0810: Three circles with third argument 60, 60, and 300 they 
        came out of the SAME tiny size, and a line called for in red came out blue. Exposing 
        parameters that don't do what they say is worse than not exposing them.
        """
        src = self._src()
        assert "def pt_draw(" not in src
        assert "drawCircle" not in src

    def test_note_uses_the_z_order_getter_not_a_font_size(self):
        """The third argument of addNote is the z-order. Verified by passing 12 and 14: 
        The notes come out identical."""
        src = self._src()
        assert "getIncNoteZOrder" in src
        assert "size: float" not in src

    def test_note_text_goes_through_json_dumps(self):
        """Rule of AGENTS.md: never interpolate raw text in the JS."""
        assert "{json.dumps(text)}" in self._src()

    def test_screenshot_writes_a_file_instead_of_returning_bytes(self):
        """A capture is tens of thousands of bytes: returning it would fill the context."""
        src = self._src()
        assert "target.write_bytes(blob)" in src
        assert '"path": str(target)' in src

    def test_screenshot_path_is_sandboxed(self):
        """Rule 2 of AGENTS.md: never build routes by concatenation."""
        src = self._src()
        assert 'safe_name_component(filename, fallback="topology")' in src
        assert "resolve_within(base, f\"{safe}.{ext}\")" in src

    def test_clear_sweeps_notes_AND_items(self):
        """getCanvasItemIds does NOT include notes: they are separate sets. 
        
        Sweeping only one left 18 notes on the screen reporting remaining=0, which 
        It's worse than not deleting: the user thinks it's clean.
        """
        src = self._src()
        assert '"getCanvasNoteIds", "getCanvasItemIds",' in src
        assert "removeCanvasItem(__ids[__i])" in src

    def test_clear_counts_what_is_left_across_both_sets(self):
        src = self._src()
        assert "__rest = __lw[__gs[__m]]() || []" in src

    def test_stale_ids_are_not_reported_as_failures(self):
        """PT leaves note ids orphaned: no text and that removeCanvasItem rejects. 
        Counting them as remaining made you believe that the cleaning failed when 
        the canvas was empty (measured: 14 orphans, clean canvas)."""
        src = self._src()
        assert "stale_ids: __stale" in src
        assert "getCanvasNoteText(__rest[__q])" in src
