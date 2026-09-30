# Changelog

## 0.9.0

Several passes handling the MCP against Packet Tracer 9.0.1, over 36 and 47 devices. What came back were not crashes: they were **fake OK**. A topology split into islands that `pt_validate_plan` passed with `error_count: 0`. A bridge that delivered the result of the previous operation — real data, from the device next door. A "CONNECTIVITY OK" with 75% loss. A crossover cable in every switch router↔, in a simulator that exists precisely to show which It goes. None of them were visible from the outside, and that's the kind of flaw that this version has He went to look for it.

It is also the first to be installed with `pip install packet-tracer-mcp`, and the the first to say its own version when a customer asks it. 

**61 tools · 349 → 473 tests.** Verified against Packet Tracer 9.0.1. 

### Packaging: the server enters PyPI 

**The server can be installed with 'pip install packet-tracer-mcp'.**

#### Added

- **Metadata published in `pyproject.toml`.** So far the package has been constructed, but could not be published in a decent way: without `readme`, the of PyPI comes out blank; without `classifiers` or `keywords`, it does not appear in any search; without `project.urls`, there is no way to return to the repo from the package. It is added all of that plus `license="MIT"` as an SPDX expression (PEP 639), with the `hatchling>=1.27` floor in `build-system` because that's where that shape starts to exist. `Twin Check` now passes without a single warning.

- **`release.yml`: publish without saving a token.** Trusted Publishing, that is, that PyPI trusts the OIDC identity of the workflow instead of a secret. A filtered token publishes any version from anywhere; identity It is only valid for this REPO, this workflow and the `pypi` environment.

Shoot with a **published** release, not with a tag push: a tag is pushed Unintentionally, publishing a release has a button in between. Before uploading Nothing compares the tag against the version of `pyproject.toml` and fails if it doesn't. match — if the release is called v0.9.0 and the file is left on 0.8.0, PyPI will be It stays with 0.8.0 forever and that number can no longer be used. `workflow_dispatch` builds and validates, but does not publish.

#### Changed

- **The sdist was 10.2 MB for 219 KB of code.** The rest were the GIFs and PNGs of `demo/`, which hatchling got for not being in `.gitignore`. No one that makes `pip install` needs the README banner. With `demo/`, `docs/`, `data/`, `mkdocs.yml` and `.github/` out of the sdist, the tarball is 312 KB — 33 times smaller.

- **The links in the README are absolute.** PyPI renders the README outside of the repo, so `src="demo/banner.png"` looks like a broken image, and it the six references to `CHANGELOG.md`, `LICENSE`, `SECURITY.md` and company. They point to `raw.githubusercontent.com` and `blob/main`, which are seen the same on GitHub and they are also seen on PyPI.

### The version that the server announced of itself

**469 -> 473 tests.**

#### Fixed

- **The server was presented with the 'mcp' library version.** A real handshake by stdio against PT 9.0.1 returned:

      {"name": "Packet Tracer MCP", "version": "1.28.1"}

  1.28.1 is the SDK; the server was on 0.8.0. The number comes out of `create_initialization_options()`, which resolves it with `self.version if self.version else pkg_version("mcp")`, and FastMCP does not expose `version` in your `__init__` or a property to get to the lowlevel server, So the fallback always won.

  It's not cosmetic: that's the number shown by Claude Desktop, Cursor, and PacketSmith in your server panel, and the one that someone copies in an issue. Worse still, it changed only when the dependency was updated — two users with the same code could report different versions, and none was that of the code. Now it is set to `_mcp_server`, with a guard in case the SDK does it rename: in that case you return to the previous behavior instead of breaking the start.

#### Added

- **`__version__` in the package**, read from the metadata installed with 
`importlib.metadata`. The version is still declared only once in 
`pyproject.toml`; copying it as literal is the classic way for a release exit announcing the previous issue. Uninstalled, drops to `0.0.0+source`, which it is an honest marker rather than a plausible lie. 

- **`tests/test_server_version.py`** — 4 tests that set the above: that the handshake says our version, it does NOT say the SDK (the SDK guard) regression), that the server name has not been moved, and that `__version__` matches `pyproject.toml`.

### The bridge token, and its first tests

**449 -> 469 tests.**

#### Fixed

- **`PT_MCP_BRIDGE_TOKEN` skipped validation.** The disk token goes through 
`_is_valid` (>=32 characters of `[A-Za-z0-9_-]`); the environment variable does not it was for nothing, so `PT_MCP_BRIDGE_TOKEN=x` left a UN token character. It's guessable, and with the token guessed, the entire defense falls against the attacking web page that this module exists to sustain: A variable designed for testing could deactivate just what it protects. Now it goes through the same gate and, if it doesn't work, `BridgeTokenError` is launched (which was defined and not used anywhere). 

It fails strongly here, the opposite of the archive, and it is not incoherent: a Corrupt file is an accident and rotating it doesn't lose anything, but a variable misplaced is an explicit decision of the one who starts the server.

#### Added

- **`bridge_token.py` has tests for the first time** — 20, being the anchor of security of the entire HTTP bridge. They cover the complete provisioning: career with `O_EXCL`, the rotation in the face of a corrupt file (empty, truncated, hand-edited), tolerance to BOM and spaces, the ephemeral fallback when the directory cannot be written, and the fingerprint does not filter the token. 

The detail that made them impossible: the IQ sets `PT_MCP_BRIDGE_TOKEN` to all the job and `get_bridge_token()` he returns in his FIRST line, so the file path would never have run there. The fixture removes that variable and redirects `token_dir()` to a TMP, so that the royal road runs also in CI and without touching the token of the user running the suite.

#### Changed

- **`skill/SKILL.md` per day with all repo** (301 -> 395 lines). Added: the table of validation codes with which to make before each one; the pattern for large topologies, when the plan does not enter through a tool parameter and you have to generate it locally and push it through the mailbox; the eight ports of the `Cloud-PT` with the frame relay warning; `d.moveToLocation(x, y)`; the three levels of the ping verdict; and a round 3 of verified findings against PT 9.0.1 -- the console stopped in the initial wizard, the IP-free interface remaining in shutdown, the WiFi association that is not by proximity, and the boot that now fails if the token in the environment is useless. 

Also fixed the `hub_spoke` limit: the skill said that it binds the hub with each spoke, not to mention that the hub runs out of ports.

### The catalog lied about the cloud

**440 -> 449 tests.**

#### Fixed

- **The catalog declared a single port for `Cloud-PT`.** Reading `getPorts()` on a live cloud in PT 9.0.1 eight come out: 

    Serial0, Serial1, Serial2, Serial3, Modem4, Modem5, Ethernet6, Coaxial7
    
The catalog had only `Ethernet6`, so `pt_add_link` rejected the others seven and `validate_plan` marked the invalid plan before the request to PT -- by ports that the device does have. A cloud was left reduced to a stub of a link, when used in large laboratories with their serials.

- **`Ethernet6` was declared as FastEthernet** with the `full_name` forced by hand. It came out well because of the override, not because of the speed. Now it takes `PortSpeed.ETHERNET` and the name is derived by itself, as in the rest of the models. The orchestrator was looking for that port with `_fast(...) `, so it was added `_ether(...) `: without that the router-cloud link disappeared silently, which is Just the kind of mute glitch we fixed in the previous batch. There are three tests that cover it.

#### Added

- `PortSpeed.MODEM`, which was missing to be able to name `Modem4` and `Modem5`.

### Third pass against PT 9.0.1 — 47 devices 

Five flaws found by checking the MCP against Packet Tracer 9.0.1 over a topology of 47 devices (6 daisy-chain routers, OSPF area 0, dual-stack, WiFi). The worst was not a crash: it was a **false OK**.

**392 -> 436 tests.**

#### Fixed

- **The validator approved topologies split into islands.** `hub_spoke` asks that the hub link with every spoke, but a 2911 has three Gigabit ports. With six routers `_link_routers` ran out of ports in the room and just didn't created the link, without warning. There were two routers left loose, without interfaces, without links and with an OSPF of `router-id 0.0.0.0` and zero networks — and `pt_validate_plan` returned `valid: true`, `error_count: 0`. A broken topology looked identical to a healthy one because all the check-ups were by device: each one existed, each one existed. port was valid, no IP clashed. The only thing that gives it away is going through the graph. New `domain/rules/topology_rules.py` with `validate_connectivity` (related components, excluding WiFi hosts that do not purposely carry cable) and `validate_routing` (OSPF without networks, router-id 0.0.0.0).

- **`pt_verify_connectivity` nunca funciono desde un router.** El JS pedia
  `getCommandPrompt()`, que SOLO existe en hosts; contra IOS tira `TypeError:
  Property 'getCommandPrompt' of object is not a function`. Justo la tool para
  verificar routing, inutil en el unico dispositivo que enruta. Verificado contra
  PT 9.0.1: los routers exponen `getCommandLine()` y los PCs exponen las dos, asi
  que ahora se usa esa para ambos. Ademas hay que **cebar la consola**: un router
  recien desplegado por el MCP nunca fue tocado por consola y sigue parado en
  `Would you like to enter the initial configuration dialog? [yes/no]:`, donde el
  `ping` se consume como respuesta al yes/no y no se ejecuta nunca.

- **Un solo AP para toda la topologia.** Con `wireless_laptops=True` se creaba un
  unico `AccessPoint-PT` cableado al switch de la LAN 1, sin importar cuantas LANs
  hubiera. Verificado contra PT 9.0.1: LT9, planificada en la LAN 5, recibia
  `192.168.0.5/24` — del pool DHCP de la LAN 1. Ahora se crea un AP por LAN que
  tenga laptops inalambricas, cada uno cableado al switch de SU LAN.

#### Added

- **`WIRELESS_AMBIGUOUS_ASSOCIATION`: el AP por LAN no alcanza, y hay que decirlo.**
  Un AP por LAN hace POSIBLE el direccionamiento correcto pero **no lo garantiza**.
  Medido contra PT 9.0.1 agregando un AP en la LAN 5 junto a dos laptops de esa
  LAN: LT10 hizo asociacion y DHCP nuevos —paso por `0.0.0.0`— y aun asi eligio el
  AP de la LAN 1 y tomo `192.168.0.13`. Recien con ese AP apagado, LT9 tomo
  `192.168.4.25`, la que le correspondia. O sea que PT **no elige el AP mas
  cercano**: entre APs que comparten el SSID por defecto la asociacion es
  arbitraria, y no hay como desambiguarla porque **PT no expone API de SSID**
  (verificado: ni el AP ni su puerto tienen `setSsid`). El plan ahora emite un
  warning en vez de prometer un direccionamiento que no controla.

- **"CONECTIVIDAD OK" con 75% de perdida.** `interpret_ping` solo decia "llego al
  menos uno", asi que 1 de 4 paquetes se reportaba igual que 4 de 4 y un enlace
  agonizante se veia sano. Nuevo `classify_ping` con tres grados
  (`ok`/`partial`/`none`); `interpret_ping` se mantiene por compatibilidad.

- **El layout se salia del canvas y se pisaba.** El ancho de columna era fijo en
  250 px y el cluster de hosts se centra en el, asi que con 4 PCs por LAN
  (4 x 80 = 320) el cluster desbordaba hacia la LAN vecina y el primer host caia
  en **x = -60**, fuera del canvas. Los servidores, ademas, se colocaban en el
  extremo derecho mientras su cable seguia yendo al PRIMER switch, dibujando
  diagonales de punta a punta. Ahora el ancho de columna se deriva de la LAN mas
  poblada, el origen deja el margen que el centrado necesita, y los servidores van
  en la columna del switch al que se cablean.

- **`pt_health_check` listaba puertos de capa 2 como "cableado sin IP".** Los
  puertos de acceso de cada 2960, los del AP y el Ethernet6 de la nube no llevan
  IP por definicion; ese ruido tapaba el unico caso que importa, el host al que no
  le llego el DHCP. Se filtra por categoria del catalogo (no por `getClassName()`,
  que clasifica por comportamiento: un 3560 responde "Router" y un 2960
  "CiscoDevice"). Un modelo que no resuelve se sigue reportando.


### Segunda pasada contra PT 9.0.1 — 36 dispositivos

Seis defectos encontrados manejando el MCP contra Packet Tracer 9.0.1 sobre una
topología de 36 dispositivos. Cuatro salieron de la primera pasada; dos más
aparecieron al verificar los arreglos **contra el dispositivo** en vez de creerle
al reporte de la tool.

**369 → 392 tests.**

#### Fixed

- **`pt_install_modules_batch` informaba puertos que nunca se crearon.** Dos cosas
  a la vez: los nombres no llevaban el slot (dos HWIC-2T en `"0/0"` y `"0/1"`
  reportaban los mismos `Serial0/0/x`), y sobre todo el envío era
  *fire-and-forget*, así que nadie miraba el retorno de `addModule` — que devuelve
  `false` sin lanzar cuando el slot no existe en ese modelo. Ahora `ports_for_slot()`
  calcula los nombres reales y el JS reporta el resultado de cada módulo **antes**
  del power-on, que era lo único que justificaba no esperar. Devuelve `installed`,
  `installed_count` y `failed`.

- **`pt_add_link` cableaba cruzado todo router↔switch.** Infería la categoría con
  `getClassName()` de PT, que clasifica por comportamiento y no por rol de red: un
  3560 responde `"Router"` (es multicapa) y un 2960 responde `"CiscoDevice"`. La
  categoría `"switch"` no llegaba nunca a las reglas de cableado. Ahora sale del
  modelo vía `category_of_model()`. No rompía la conectividad —el auto-MDIX de PT
  compensa— pero en un simulador educativo enseñaba el cable equivocado.

- **`pt_rename_device` dejaba renombrar a un nombre ya ocupado.** PT lo acepta sin
  chistar y a partir de ahí `getDevice(nombre)` solo resuelve a uno: el otro queda
  en el canvas pero inalcanzable por nombre, y cualquier tool que lo referencie
  trabaja en silencio sobre el equivocado. `pt_add_device` sí validaba; faltaba en
  la otra vía de entrada.

- **`pt_workspace_options` fallaba siempre en `show_device_labels`.**
  `setHideDevLabel` toma **dos** argumentos, no uno. Además cada setter va ahora en
  su propio try/catch: antes uno que fallara abortaba la tanda dejando aplicados los
  anteriores y devolviendo error, o sea "falló" con la mitad de los cambios puestos.
  Se reportan `applied` y `failed`, y el contador refleja lo que PT aceptó.

- **`pt_fix_plan` dejaba el plan internamente inconsistente.** Corregía el puerto en
  el enlace pero no en `device.interfaces`, así que la IP se quedaba en una interfaz
  que ya no usaba ningún enlace. Ahora la migra, IPv4 e IPv6.

#### Changed

- Documentación de slots corregida: el **1941 tiene 2 slots HWIC** (`"0/0"`,`"0/1"`),
  no 4. El 2911 sí acepta `"0/0".."0/3"`. Medido contra PT 9.0.1; decía `0/0..0/3`
  para ambos en el docstring, en `settings.py` y en la skill.
- `WORKSPACE_SETTERS` / `workspace_setter_call()` salen del closure a nivel de
  módulo. La polaridad (PT expone dos opciones en negativo) es justo la clase de
  regla que un refactor puede invertir sin que ningún `assert "..." in src` se
  entere, así que sus tests ahora ejecutan la lógica en vez de leer el fuente.

### El bridge entregaba el resultado de otra operacion

El bridge HTTP entregaba resultados a la operación equivocada. No fallaba: devolvía
datos reales de Packet Tracer, del dispositivo de al lado.

**350 → 369 tests.** Verificado contra Packet Tracer 9.0.1 por el canal HTTP.

La comprobación en vivo salió del propio bug: `pt_add_module` sobre un 2911 tardó
**15 s** —el power-cycle del router se pasa de largo— y el caller esperó sus 15 s
enteros en vez de rendirse a los 9. El módulo se instaló (aparecieron `Serial0/0/0`
y `Serial0/0/1`), o sea que el resultado llegó tarde y quedó huérfano; la llamada
siguiente, un `pt_query_topology`, devolvió **su** topología y no ese resultado. Es
el cruce que antes ocurría, esta vez con PT de verdad.

#### Fixed

- **Los resultados del bridge HTTP se correlacionan por `rid`.** Eran una cola FIFO
  global: quien pedía un resultado se llevaba el primero que hubiera, fuera suyo o no.
  Bastaba que una operación se pasara de su ventana para que su resultado quedara
  huérfano y lo consumiera la siguiente — y a partir de ahí, cada llamada devolvía la
  anterior. Ahora cada operación genera su `rid`, que viaja dentro del JS inyectado y
  PT devuelve al postear. **La extensión no cambia:** nunca construye la URL de
  `/result`, solo ejecuta el JS que le llega, así que el `.pts` sigue siendo el mismo.

- **El caller fija cuánto espera su resultado.** `GET /result` esperaba 9 segundos
  fijos mientras los callers pedían hasta 45. De las 36 llamadas a
  `_bridge_send_and_wait`, **26 pedían más de 9 s**: todas recibían un 204 prematuro y
  se daban por fallidas aunque PT estuviera trabajando bien. El `wait` ahora viaja en
  la petición, con un techo de 60 s para que una espera absurda no ate un thread.

- **Bases de red inválidas explican qué pasó.** `base_network` llegaba cruda hasta
  `IPPlanner`: una `/25` moría con `new prefix must be longer`, una `/24` con un
  `StopIteration` desnudo al pedir la segunda LAN, y un texto cualquiera con
  `AddressValueError`. Los tres salían como stacktrace. Ahora `TopologyRequest` rechaza
  las bases que no dan ni una subred, y el agotamiento real —que depende de cuántas
  LANs pida la topología, y por eso no se sabe hasta el planner— dice cuántas caben y
  qué prefijo usar.

#### Removed

- `PTCommandBridge.send()` y `.send_and_wait()`, que nadie llamaba: el adaptador habla
  con el bridge por HTTP, no por métodos de la instancia. Llevaban una segunda copia
  del mismo bug de correlación y un parámetro `timeout` que no se usaba.

## 0.8.0

El servidor podía construir una red y leerla, pero no mostrarla. Esta versión
cierra eso: el agente ahora entrega un diagrama, no una descripción.

**58 → 61 tools · 319 → 349 tests.** Verificado contra Packet Tracer 9.0.0.0810.

### Added

- **`pt_screenshot`** — captura el canvas lógico a un archivo y devuelve su ruta.
  No devuelve la imagen: son decenas de miles de bytes y llenarían el contexto
  del modelo con datos que nadie puede mirar. PNG por defecto, porque comprime un
  diagrama mucho mejor que JPG (33 KB contra 105 KB sobre el mismo canvas).
- **`pt_add_note`** — escribe una nota sobre el canvas: etiquetar una subred,
  marcar un área OSPF, nombrar un troncal.
- **`pt_clear_annotations`** — borra notas y dibujos. Nunca toca dispositivos ni
  enlaces.

Juntas permiten **topologías auto-documentadas**: construir con `pt_full_build`,
etiquetar cada subred y enlace, y capturar — un diagrama listo para una clase a
partir de un solo prompt.

### Limitación conocida

**No hay tool de dibujo.** Packet Tracer dibuja líneas y círculos en el canvas,
pero no de forma útil desde una extensión: el argumento donde iría el tamaño
resultó controlar el orden de apilado —tres círculos pidiendo 60, 60 y 300
salieron todos del mismo tamaño diminuto— y los colores no producen el color
pedido. Antes que exponer parámetros que no hacen lo que dicen, la anotación
queda limitada a notas de texto. El tamaño de fuente tampoco es configurable,
por la misma razón.

## 0.7.0

Until now the server could build a network but not look at one. It planned,
validated and deployed, and if the result misbehaved the model was blind — it
could redeploy and hope. This release adds the other half: reading the live
devices back, and explaining what they decided and why.

**46 → 58 tools · 188 → 319 tests.** Verified against Packet Tracer 9.0.0.0810.

### Fixed

- **`pt_full_build(deploy=True)` now deploys.** It always went to the clipboard,
  so with the bridge connected it reported `Validación: PASS` and left the canvas
  empty — the main pipeline silently built nothing. It now deploys through the
  `pt_live_deploy` path (device and link verification, plus the reconcile pass
  for the devices PT drops) and falls back to the clipboard only when no channel
  exists.

### Added — reading the live topology

- **`pt_audit_security`** — grades the effective configuration of every IOS
  device: missing `enable secret`, credentials stored reversibly, `service
  password-encryption` off, no local users, no MOTD banner, and a
  config-register left at `0x2142` (which discards the startup-config on the
  next reboot). Findings carry a severity and a suggested fix.
  Credentials never leave the device — only the algorithm label is transmitted,
  because a hash in a tool result ends up in the model's context and the client's
  logs.
- **`pt_inspect_ports`** — per-port line and protocol status, MAC, addressing,
  duplex, bandwidth, MTU, delay, CDP, DHCP-client state, NAT mode and applied
  ACLs. Flags cabled-but-down and line-up-protocol-down.
- **`pt_read_vlans`** — the switch's real VLAN database, separating your VLANs
  from the ones PT ships with.
- **`pt_device_power`** — power a device off and on with read-back, to simulate
  an outage or force a reboot.

### Added — simulation

- **`pt_read_packet_trace`** — the simulation event list: per frame the path,
  the outcome, and **PT's own per-OSI-layer explanation of each decision**. A
  failing ping stops being "no reply" and becomes a cause, e.g. *"The next-hop IP
  address is not in the ARP table. The ARP process buffers this packet."*
- **`pt_simulation_mode`** / **`pt_simulation_step`** — switch between Realtime
  and Simulation, and move the event list forward, back or to the start.

### Added — telemetry, QoS and backup

- **`pt_apply_netflow`** — create, reconfigure or remove a NetFlow exporter
  (collector address, UDP port, version, source interface, monitors) and read the
  result back. Reapplying a name reconfigures rather than duplicating.
- **`pt_read_qos`** — class-maps and policy-maps with their CLI form. Read-only:
  QoS cannot be created programmatically, so author it with IOS CLI and use this
  to confirm it landed.
- **`pt_backup_config`** — the device's real startup-config plus serial,
  config-register, boot images and uptime. Optional full XML dump.
- **`pt_project_metadata`** — saved filename, PT version, description and
  device/link count; flags a project that has never been saved.
- **`pt_workspace_options`** — auto-cabling (turn it off before a scripted build
  if you need links on exact interfaces) and access to the real network, plus the
  canvas labels that decide whether a screenshot is readable.

### Improved

- **`pt_apply_interface_tuning`** gains `ospf_dead_interval` and OSPF
  authentication in both message-digest and plaintext form. The key is emitted
  before authentication is enabled — the other order leaves the interface
  demanding auth with nothing to answer and the adjacency drops. `dead <= hello`
  is rejected, since mismatched timers mean no adjacency forms at all.
- **`pt_set_port`** gains `zone_member` (Zone-Based Firewall), `proxy_arp` —
  turning it off is routine hardening, since a router answering ARPs that are not
  its own leaks topology — and `ike` for IPsec.

Both were extended rather than given their own tools: `pt_apply_interface_tuning`
already set the other OSPF knobs and `pt_set_port` already applied low-level port
attributes, so separate tools would have been mostly duplicate.

### Known limitations

- **No `pt_send_pdu`.** Packet Tracer does not let an extension originate a
  packet the way the GUI's *Add Simple PDU* button does. Generate traffic with a
  real ping (`pt_verify_connectivity`) and then read the trace.
- **QoS is read-only.** Class-maps and policy-maps cannot be created through the
  API; author them with IOS CLI.
- **`zone_member` needs its zone to exist.** Setting it succeeds, but the
  interface line only appears once a matching `zone security` is configured.

## 0.6.0

- The live-deploy bridge authenticates with a per-machine token. Earlier versions
  had an unauthenticated bridge: any web page open while Packet Tracer was
  running could execute code inside it. **Requires the V5 extension.**
