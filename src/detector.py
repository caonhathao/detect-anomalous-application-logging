import torch
from transformers import BertConfig, BertForMaskedLM

MODEL_PATH = "models/saved_bert/logbert_trained.pth"


class LogBertAnalyzer:
    def __init__(self, vocab_size, max_len=10):
        self.vocab_size = vocab_size
        self.max_len = max_len
        self.device = torch.device("cpu")

        self.mask_token_id = vocab_size

        # 1. Khởi tạo cấu trúc LogBERT (Tiny BERT cho nhẹ)
        config = BertConfig(
            vocab_size=vocab_size + 10,
            hidden_size=128,
            num_hidden_layers=2,
            num_attention_heads=2,
            max_position_embeddings=512
        )
        self.model = BertForMaskedLM(config).to(self.device)
        self.model.load_state_dict(torch.load(MODEL_PATH, map_location=self.device))
        self.model.eval()

    def prepare_sequences(self, event_ids):
        sequences = []
        labels = []
        indices = []

        # Tạo cửa sổ trượt
        if len(event_ids) < self.max_len:
            return [], [], []

        for i in range(len(event_ids) - self.max_len):
            # Input: sequence độ dài max_len
            seq = event_ids[i: i + self.max_len]
            # Label: chính là token tiếp theo (để kiểm tra xem model đoán đúng ko)
            next_token = event_ids[i + self.max_len]

            sequences.append(seq)
            labels.append(next_token)
            indices.append(i + self.max_len)  # Index của dòng log mục tiêu

        return sequences, labels, indices

    def detect_anomalies(self, event_ids, top_k=5):
        sequences, labels, line_indices = self.prepare_sequences(event_ids)
        if not sequences:
            return {
                "total_logs": len(event_ids),
                "total_windows": 0,
                "anomaly_count": 0,
                "anomalies": []
            }

        # Chuyển sang Tensor
        input_ids = torch.tensor(sequences, dtype=torch.long).to(self.device)

        batch_size = input_ids.shape[0]
        mask_column = torch.full((batch_size, 1), self.mask_token_id, dtype=torch.long).to(self.device)
        masked_input = torch.cat([input_ids, mask_column], dim=1)

        anomalies = []

        with torch.no_grad():
            outputs = self.model(masked_input)
            predictions = outputs.logits  # Shape: [batch, sequence_length, vocab_size]

            # Chúng ta chỉ quan tâm dự đoán ở vị trí cuối cùng của chuỗi
            last_token_logits = predictions[:, -1, :]

            # Lấy top K dự đoán có xác suất cao nhất
            probs = torch.softmax(last_token_logits, dim=-1)
            top_preds = torch.topk(probs, k=top_k, dim=-1).indices

        # Kiểm tra: Nếu token thực tế (labels) KHÔNG nằm trong top K dự đoán -> Bất thường
        for idx, (real_token, pred_tokens) in enumerate(zip(labels, top_preds)):
            if real_token not in pred_tokens.tolist():
                anomalies.append({
                    "LineId": line_indices[idx] + 1,
                    "EventId": real_token,
                    "Confidence": probs[idx, real_token].item()
                })

        return {
            "total_logs": len(event_ids),
            "total_windows": len(sequences),
            "anomaly_count": len(anomalies),
            "anomalies": anomalies
        }
