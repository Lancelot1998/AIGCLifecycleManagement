# Blockchain-empowered AIGC product lifecycle manageent in edge networks

## In this project, we implement:

### 1.The reputation based Edge Service Provider (ESP) selection scheme over a P2P network.

We have three clients, three ESPs and one server. The clients send service request to ESPs, and evaluate the service quality.

In this way, the local reputation can be created.

Then, we implement a Peer-to-Peer network (coordinated by a server), with which clients can exchange local reputation.

After weighting received local reputation, the overall reputation can be created.

Finally, the reputation can be calcualted by combining local reputation and overall reputation.

More details can be found in [Multi-weight Subjective Logic](https://arxiv.org/pdf/1809.08387.pdf)


> How to run the code?

> Of course, you need some libraries, e.g., Pytorch and Numpy.

> Run server.py

> Run client1.py

> Run client2.py

> Run client3.py

> The generated three-element tuple, e.g., [0.21, 0.335, 0.488] is the reputation for three ESPs

### 2.The blockchain platform.

The blockchain is built atop [Blockchain Prototype](https://github.com/Lancelot1998/Space-structured_Blockchain)

Still under refinement. The running instructions will be released soon.

### Some important references/real-world examples:

