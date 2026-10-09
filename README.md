<b>Install on a fresh copy of ubuntu</b>

<b>1)install MCP packet tracer</b>

git clone https://github.com/hanley/MCP-PT.git

cd MCP-PT

sudo apt install python3.12-venv

python3 -m venv mcp-pkt

source mcp-pkt/bin/activate

pip install -e .

<b>2)install claude</b>

sudo apt update

sudo apt install curl ca-certificates gnupg -y


<i>Update Claude repository</i>
```
tmp_key="$(mktemp)"
tmp_gnupg="$(mktemp -d)"
status_code=1

if curl -fsSLo "$tmp_key" https://downloads.claude.ai/claude-desktop/key.asc && \
   key_metadata="$(GNUPGHOME="$tmp_gnupg" gpg --batch --show-keys --with-colons "$tmp_key")"; then
    fingerprint="$(printf '%s\n' "$key_metadata" | awk -F: '$1 == "fpr" {print $10; exit}')"
    printf 'Anthropic key fingerprint: %s\n' "$fingerprint"

    if [ "$fingerprint" = "31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE" ]; then
        sudo install -Dm644 "$tmp_key" /usr/share/keyrings/claude-desktop-archive-keyring.asc
        status_code=$?
    else
        echo "Unexpected Anthropic signing key fingerprint" >&2
    fi
else
    echo "Anthropic key download or inspection failed" >&2
fi

rm -rf "$tmp_key" "$tmp_gnupg"
[ "$status_code" -eq 0 ]
```




<i>sign the app</i>
```
arch="$(dpkg --print-architecture)"

case "$arch" in
    amd64|arm64)
        echo 'deb [arch=amd64,arm64 signed-by=/usr/share/keyrings/claude-desktop-archive-keyring.asc] https://downloads.claude.ai/claude-desktop/apt/stable stable main' \
        | sudo tee /etc/apt/sources.list.d/claude-desktop.list > /dev/null
        ;;
    *)
        printf 'Unsupported Claude Desktop architecture: %s\n' "$arch" >&2
        false
        ;;
esac

```


sudo apt update

apt-cache policy claude-desktop


sudo apt install claude-desktop -y

claude-desktop


<b>3)install ollama</b>

cd ~

curl -fsSL https://ollama.com/install.sh | sh


export ANTHROPIC_BASE_URL=http://localhost:11434


ollama pull qwen2.5:3b


sudo systemctl edit ollama

```
[Service]

Environment="OLLAMA_HOST=0.0.0.0:11434"
```

<img width="940" height="433" alt="image" src="https://github.com/user-attachments/assets/0cc6276c-2e3f-4e99-abc3-f97299f91cbe" />
 
sudo systemctl daemon-reload

sudo systemctl restart ollama



curl http://VM_IP_ADDRESS:11434/api/tags


<b>4)Install mcp ollama</b>

cd ~

sudo apt install npm

git clone https://github.com/MikeyBeez/mcp-ollama.git


cd mcp-ollama

npm install --save-dev @types/node-fetch@2

npm run build

npm uninstall node-fetch

npm install node-fetch@2

rm -rf dist

npm run build



<b>Install mcp packet tracer - continue</b>

cd ~/MCP-PT

source mcp-pkt/bin/activate

pip install -e . => install using local python file

python -m packet_tracer_mcp --stdio

**if working, no error message. Control-C to exit


<b>5)Install Packet Tracer</b>

Download from Cisco Netacad

cd ~/Downloads

sudo apt install ./CiscoPacketTracer_901_Ubuntu_64bit.deb



<b>6)If import given OVA, OVA comes with all the above installed</b>

Start claude-desktop and login for claude to generate the claude_desktop_config.json.

Shutdown claude-desktop before doing the steps below.


cd MCP-PT

source mcp-pkt/bin/activate



nano /home/analyst/.config/Claude/claude_desktop_config.json
```

"mcpServers": {

    "ollama": {
    
      "command": "node",
      
      "args": ["/home/analyst/mcp-ollama/dist/index.js"],
      
      "env": {
      
        "OLLAMA_BASE_URL": "http://< VM_IP_ADDRESS>:11434"
        
      }
      
    }
    
  },
  
```
**When using claude-desktop, no way to choose the model, must specify in the prompt such as

"Use the Ollama MCP server to list the available Ollama models.

Use qwen2.5:3b through Ollama to answer my next networking question."


or

"Use the Ollama MCP server and ask qwen2.5:3b:

Explain how to configure a VLAN on a Cisco IOS switch."


nano /home/analyst/.config/Claude/claude_desktop_config.json

```
, "packet-tracer": { 

    "command": "/home/analyst/MCP-PT/mcp-pkt/bin/python", 
    
    "args": [ "-m", "packet_tracer_mcp", "--stdio" ] 
    
    }
    
```
<img width="940" height="614" alt="image" src="https://github.com/user-attachments/assets/c76f2111-332e-40e4-a5ad-c78d0818f51a" />

Use web browser to go to https://github.com/Mats2208/MCP-Packet-Tracer to download V5.2.pts

<img width="940" height="251" alt="image" src="https://github.com/user-attachments/assets/94f0ec26-8777-46a9-abe1-299b6475e4d4" />

Add to Scripting > Configure PT Script Modules
<img width="438" height="428" alt="image" src="https://github.com/user-attachments/assets/d57fc13e-d89b-4cc4-bcf0-623b695cfe18" />

<img width="940" height="524" alt="image" src="https://github.com/user-attachments/assets/cae010da-1450-4aa0-baab-2f28b73e561b" />

Create token on terminal if No MCP token found on this machine.
 <img width="539" height="53" alt="image" src="https://github.com/user-attachments/assets/a5fc2f82-c5a7-43ac-9db8-51e9f9907f5b" />

Do this on the Ubuntu machine where you run packet_tracer_mcp:

cd MCP-PT

source mcp-pkt/bin/activate


echo "$PT_MCP_BRIDGE_TOKEN"

If it is empty, generate one:

export PT_MCP_BRIDGE_TOKEN=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")


Need to ask the prompt

"Use the Packet Tracer MCP tool pt_bridge_status and tell me the connection status."

To allow the connection from claude desktop


<B><U>How to start the system</U></B>

cd MCP-PT

source mcp-pkt/bin/activate

export PT_MCP_BRIDGE_TOKEN=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")

python -m packet_tracer_mcp --stdio

open another terminal (don’t start claude from menu)

claude-desktop

import packet tracer skill into claude

start packet tracer

if MCP control center still not connected,

send a prompt in claude-desktop

“Use the ollama MCP and Packet Tracer MCP tool pt_bridge_status and tell me the connection status.”

Restart packet



Example Prompt:

Using ollama mcp, Using the Packet Tracer MCP tools, create a topology plan with

2 routers, 2 switches and 4 PCs.

Do not deploy it yet.

<img width="684" height="573" alt="image" src="https://github.com/user-attachments/assets/502c8a35-be5b-416a-b569-55cc7ad0edb8" />

<img width="940" height="914" alt="image" src="https://github.com/user-attachments/assets/844b61c8-8f0a-4af4-99a0-b02fa4e2127c" />

Using ollama mcp, Validate the topology.

<img width="940" height="654" alt="image" src="https://github.com/user-attachments/assets/0e432298-a4f7-4905-95c7-e8bd91cabab9" />

<img width="940" height="501" alt="image" src="https://github.com/user-attachments/assets/38c9a198-921e-4c44-b090-c8619c819bb8" />

Using ollama mcp, deploy the topology into Packet Tracer.


<img width="940" height="658" alt="image" src="https://github.com/user-attachments/assets/4a72cd05-94dc-43bf-bc58-36335ecb991e" />



