"""
Hybrid DLT-PINNs EWS IPS — a DDoS Early Warning System / Intrusion Prevention System.

A neural network (see ../model.py) is trained only on benign traffic to learn the
per-second signature of "normal". The engine scores network traffic second by
second by how far it departs from that baseline and raises graded LOW/MED/HIGH
early warnings. `preprocessing.py` holds the shared feature pipeline and
`service.py` adds job/progress tracking so results stream to the dashboard as they
are produced.
"""
