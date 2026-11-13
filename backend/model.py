"""
Neural network used by Approach 1 (Hybrid DLT-PINNs).

`DatasetGeneratorNN` learns, from benign-only traffic, the expected per-second
feature signature of "normal". At analysis time each second is scored by how far
its features sit from this learned baseline.

This class must keep the module path ``model.DatasetGeneratorNN``: the pre-trained
weights in ``models/hybrid/*.pkl`` were pickled against that path, so moving or
renaming this file would stop them loading.
"""
import torch.nn as nn


class DatasetGeneratorNN(nn.Module):
    def __init__(self, output_dim):
        super().__init__()
        layers = [nn.Linear(1, 30), nn.Tanh()]
        for _ in range(4):
            layers += [nn.Linear(30, 30), nn.Tanh()]
        layers += [nn.Linear(30, output_dim), nn.Sigmoid()]
        self.net = nn.Sequential(*layers)

    def forward(self, x):
        return self.net(x)
