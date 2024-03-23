# Advanced InfoSec Properties

This repository contains scripts designed to serve as examples of advanced information security properties, namely Perfect Forward Secrecy (PFS) and Post-Compromise Security (PCS). Those examples were used during the workshop _"Introduction to basic and advanced information security properties"_, which took place at the 17h Regional School on Computer Networks (ERRC'19).

### Perfect Forward Secrecy (PFS)
PFS is a property of secure communication protocols that ensures that confidentiality of sessions when
long term keys are compromised. This means that when attackers obtain a participant's or server's private keys, they are unable to decrypt past communications.

### Post-Compromise Security (PCS)
PCS is a property that ensures that future sessions of a communication protocol are secure even after keys are compromised. This is achieved by updating the keys in such a way that future keys cannot be predicted or derived from the compromised keys.

## Requirements

To run the scripts in this repository, you will need:

- **Python 3**: Ensure you have Python 3 installed on your system. You can download it from [the official Python website](https://www.python.org/downloads/).

- **Libraries**: The scripts depend on the following Python libraries:
  - `hkdf`
  - `cryptography`

You can install these libraries using `pip`, the Python package installer. Run the following command in your terminal:

```
pip install hkdf cryptography
```
