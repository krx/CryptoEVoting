# Crypto I - E-Voting

### Initial setup

Install the necessary dependencies with:

```bash
(ﾉ◕ヮ◕)ﾉ*:･ﾟ✧ pip install -r requirements.txt ✧ﾟ･: *ヽ(◕ヮ◕ヽ)
```

### Start Servers

The registrar and board servers can be started by running:

```bash
(ﾉ◕ヮ◕)ﾉ*:･ﾟ✧ ./startservers.sh ✧ﾟ･: *ヽ(◕ヮ◕ヽ)
```

Or:

```bash
(ﾉ◕ヮ◕)ﾉ*:･ﾟ✧ python2 registrar.py & python2 board.py ✧ﾟ･: *ヽ(◕ヮ◕ヽ)
```

### Start Voter Client

There are two versions of the voter client. For a console version, run:

```bash
(ﾉ◕ヮ◕)ﾉ*:･ﾟ✧ python2 voter.py ✧ﾟ･: *ヽ(◕ヮ◕ヽ)
```

For the GUI version, run:

```bash
(ﾉ◕ヮ◕)ﾉ*:･ﾟ✧ python2 voterclient.py ✧ﾟ･: *ヽ(◕ヮ◕ヽ)
```

## Usage

### Candidates

Candidates are listed, one per line, in candidates.txt

### Registrar

Once it's running, don't touch it, you don't need to

### Board

The board has 3 phases, hit `enter` to cycle through them (and quit at the end)

1. Registration
2. Voting
3. Tallying and quit

### Voter client

Instructions included in client

### Voters

voters.db can be edited/deleted to change the registration status of voters
