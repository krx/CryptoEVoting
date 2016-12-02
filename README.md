# Crypto I - E-Voting

### Initial setup

Install the necessary dependencies with:

```bash
🐧 pip install -r requirements.txt
```

### Start Servers

The registrar and board servers can be started by running:

```bash
🐧 ./startservers.sh
```

Or:

```bash
🐧 python2 registrar.py & python2 board.py
```

### Start Voter Client

There are two versions of the voter client. For a console version, run:

```bash
🐧 python2 voter.py
```

For the GUI version, run:

```bash
🐧 python2 voterclient.py
```

## Usage

### Registrar

Once it's running, don't touch it, you don't need to

### Board

The board has 3 phases, hit `enter` to cycle through them (and quit at the end)

1. Registration
2. Voting
3. Tallying and quit

### Voter client

Instructions included in client
