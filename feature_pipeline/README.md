# Module: Feature Pipeline
**Owner: Ilma Rehman**

## Files
| File | Purpose |
|---|---|
| `extractor.py` | Converts flow packets → feature vector dict |
| `preprocessor.py` | StandardScaler fit/transform, saves `scaler.pkl` |
| `pipeline.py` | Reads `packet_queue`, extracts, pushes to `ml_queue` |
| `dataset_builder.py` | Batch builds labeled CSV from PCAP for training |

## Data Contract
**Input** from `network_layer.capture.packet_queue` — raw packet dicts.  
**Output** to `ai_engine` via `feature_pipeline.pipeline.ml_queue` — feature dicts.

## Feature List
See `extractor.py → FEATURES` list. Coordinate with Kunal before adding/removing.
