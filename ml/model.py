"""PyTorch neural network architecture for payload classification (CNN/BiLSTM)."""

import torch
import torch.nn as nn


class PayloadClassifier(nn.Module):
    """Character-level CNN + BiLSTM hybrid model for SQLi and XSS detection."""

    def __init__(
        self,
        vocab_size: int,
        embed_dim: int = 64,
        num_classes: int = 3,
        hidden_dim: int = 64,
        num_filters: int = 64,
    ):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.conv1 = nn.Conv1d(in_channels=embed_dim, out_channels=num_filters, kernel_size=3, padding=1)
        self.relu = nn.ReLU()
        self.lstm = nn.LSTM(
            input_size=num_filters,
            hidden_size=hidden_dim,
            batch_first=True,
            bidirectional=True,
        )
        self.dropout = nn.Dropout(0.3)
        self.fc = nn.Linear(hidden_dim * 2, num_classes)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: [batch_size, seq_len]
        embed = self.embedding(x)  # [batch_size, seq_len, embed_dim]
        conv_in = embed.permute(0, 2, 1)  # [batch_size, embed_dim, seq_len]
        conv_out = self.relu(self.conv1(conv_in))  # [batch_size, num_filters, seq_len]
        lstm_in = conv_out.permute(0, 2, 1)  # [batch_size, seq_len, num_filters]
        lstm_out, _ = self.lstm(lstm_in)  # [batch_size, seq_len, hidden_dim * 2]
        # Pool across sequence dimension
        pooled, _ = torch.max(lstm_out, dim=1)  # [batch_size, hidden_dim * 2]
        out = self.fc(self.dropout(pooled))  # [batch_size, num_classes]
        return out
