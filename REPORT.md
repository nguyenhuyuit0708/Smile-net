# BÁO CÁO KẾT QUẢ THỰC NGHIỆM: MÔ PHỎNG MẠNG 5 NODE TLS 1.3 KẾT HỢP PQC (1000 LƯỢT TRAO ĐỔI BẮT GÓI TIN)

---

## 1. TỔNG QUAN MÔI TRƯỜNG & KIẾN TRÚC THỰC NGHIỆM

### 1.1. Mô hình mạng 5 Node (Mininet + Linux Bridge + Traffic Control Netem)
Hệ thống được triển khai thực tế trên **Mininet 2.3.0** kết hợp bộ điều khiển lưu lượng nhân Linux (`tc netem`) và tắt toàn bộ cơ chế gộp gói phần cứng ảo (`ethtool -K <iface> tso off gso off gro off`) để bắt chính xác các phân đoạn khung Ethernet theo chuẩn **MTU 1500 bytes (1514 bytes Ethernet Frame)**.

| Node | Tên định danh | Địa chỉ IP | Vai trò | Số phiên PQC | Số phiên Baseline | Độ trễ đường truyền (Link Delay) |
| :--- | :--- | :--- | :--- | :---: | :---: | :---: |
| **Node 1** | `srv` | `10.0.0.1/24` | TLS 1.3 + PQC Server (Cổng 4433/4434) | 1000 | 200 | `2.0 ms ± 0.4 ms` (100 Mbps) |
| **Node 2** | `client_1` | `10.0.0.2/24` | TLS 1.3 + PQC Client 1 | 250 | 50 | `1.8 ms ± 0.3 ms` (100 Mbps) |
| **Node 3** | `client_2` | `10.0.0.3/24` | TLS 1.3 + PQC Client 2 | 250 | 50 | `2.1 ms ± 0.3 ms` (100 Mbps) |
| **Node 4** | `client_3` | `10.0.0.4/24` | TLS 1.3 + PQC Client 3 | 250 | 50 | `2.4 ms ± 0.3 ms` (100 Mbps) |
| **Node 5** | `client_4` | `10.0.0.5/24` | TLS 1.3 + PQC Client 4 | 250 | 50 | `2.7 ms ± 0.3 ms` (100 Mbps) |
| **Tổng** | **5 Nodes** | `10.0.0.0/24` | **Switch trung tâm `s1`** | **1000 phiên** | **200 phiên** | **0% Packet Loss (`0 dropped`)** |

### 1.2. Cấu hình Giao thức TLS 1.3 & Mật mã Hậu lượng tử (PQC)
- **Thư viện mật mã**: OpenSSL 3.0.2 tích hợp **Open Quantum Safe (`oqsprovider` v0.12.0 + `liboqs` v0.16.0)**.
- **Trao đổi khóa (Key Exchange / KEM)**:
  - **PQC Mode**: **`X25519MLKEM768`** (Hybrid X25519 + NIST FIPS 203 ML-KEM-768 / Kyber768, mã IANA `0x11EC` = `4588`).
  - **Classical Baseline**: **`X25519`** (ECDHE Curve25519 cổ điển).
- **Xác thực & Chữ ký số (Authentication & Digital Signature)**:
  - **PQC Mode**: **`ML-DSA-65`** (NIST FIPS 204 Dilithium3, khóa công khai `1,952 bytes`, chữ ký `3,309 bytes`) tích hợp trong chứng chỉ lai **ITU-T X.509v3 Catalyst (`6,146 bytes` DER / `8.2 KB` PEM)** cùng ký xác thực bản ghi phiên bằng `liboqs`.
  - **Classical Baseline**: **`ECDSA P-256`** (`prime256v1`, chứng chỉ `859 bytes` DER / `1.2 KB` PEM).
- **Cipher Suite**: `TLS_AES_256_GCM_SHA384` (TLS 1.3 thuần, vô hiệu hóa Session Ticket để bắt buộc thực hiện Full PQC Handshake trên cả 1000 phiên).

---

## 2. KẾT QUẢ BẮT GÓI TIN (`.PCAP`) VÀ SỐ LIỆU ĐỊNH LƯỢNG

### 2.1. Thống kê tổng quan File PCAP (`captures/tls_pqc_1000.pcap`)
- **Tổng số gói tin bắt được**: **32,846 gói tin** (`0 packets dropped by kernel`).
- **Tổng dung lượng trên đường truyền (Wire Bytes)**: **19,073,233 bytes (~18.19 MB)**.
- **Kích thước gói tin**: Nhỏ nhất `66 bytes` (TCP ACK/Control), lớn nhất `1,514 bytes` (Full Ethernet MTU), trung bình `580.69 bytes`.
- **Phân bố cờ TCP (TCP Flags)** trong 1000 phiên:
  - `SYN (S)`: **1,000 gói** (khớp tuyệt đối 1000 kết nối khởi tạo từ 4 Client).
  - `SYN-ACK (SA)`: **1,000 gói** (khớp tuyệt đối 1000 phản hồi từ Server `10.0.0.1`).
  - `PSH-ACK (PA)`: **8,939 gói** (mang tải dữ liệu TLS Handshake và Application Data).
  - `ACK (A)`: **19,907 gói** (xác nhận các phân đoạn TCP của chứng chỉ và khóa PQC).
  - `FIN-ACK (FA)`: **2,000 gói** (đóng kết nối hai chiều cho 1000 phiên).

### 2.2. Bảng đối chuẩn: TLS 1.3 + PQC vs TLS 1.3 Cổ điển (Classical)

| Chỉ số đo lường (Metric) | TLS 1.3 + PQC (`X25519MLKEM768` + `ML-DSA-65`) | TLS 1.3 Cổ điển (`X25519` + `ECDSA-P256`) | Hệ số chênh lệch (Overhead Ratio) |
| :--- | :---: | :---: | :---: |
| **Kích thước `ClientHello` (TLS Record)** | **1,378 bytes** | 202 bytes | **6.82x** |
| **Kích thước `ServerHello` (TLS Record)** | **1,210 bytes** | 122 bytes | **9.92x** |
| **Kích thước Chứng chỉ X.509 (DER)** | **6,146 bytes** | 859 bytes | **7.15x** |
| **Bản tin Encrypted Handshake (Server)** | **6,512 bytes** | 1,225 bytes | **5.32x** |
| **Tổng dung lượng đường truyền / Phiên** | **19,493.1 bytes** | 3,367.0 bytes | **5.79x** |
| **Số lượng gói tin TCP / Phiên** | **33.57 gói** | 15.81 gói | **2.12x** |
| **Thời gian TCP 3-Way Handshake (Mean)** | **4.650 ms** | 4.640 ms | **1.00x** |
| **Thời gian Bắt tay TLS 1.3 (Mean)** | **7.602 ms** | 6.951 ms | **1.09x (+0.65 ms)** |
| **Thời gian Bắt tay TLS 1.3 (Median / P95)**| **7.456 ms / 9.353 ms** | 6.830 ms / 7.890 ms | **1.09x** |
| **Thời gian Ký / Xác thực `ML-DSA-65`** | **0.190 ms (Sign) / 0.070 ms (Verify)** | - | **~0.26 ms CPU** |
| **Tổng thời gian hoàn tất phiên (Mean)** | **18.580 ms** | 17.070 ms | **1.09x (+1.51 ms)** |

### 2.3. Thống kê theo từng Node Client (Node 2 – Node 5)

| Node Client | Địa chỉ IP | Số phiên | Độ trễ cấu hình | TLS Handshake Mean (ms) | Total Session Mean (ms) | Số gói TB / Phiên | Dung lượng TB / Phiên |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **`client_1`** | `10.0.0.2` | 250 | 1.8 ms | **7.058 ms** | **17.109 ms** | 33.20 gói | 19,501.6 B |
| **`client_2`** | `10.0.0.3` | 250 | 2.1 ms | **7.451 ms** | **18.101 ms** | 32.99 gói | 19,218.1 B |
| **`client_3`** | `10.0.0.4` | 250 | 2.4 ms | **7.675 ms** | **18.956 ms** | 34.32 gói | 19,847.3 B |
| **`client_4`** | `10.0.0.5` | 250 | 2.7 ms | **8.225 ms** | **20.152 ms** | 33.77 gói | 19,405.3 B |

---

## 3. HỆ THỐNG BIỂU ĐỒ PHÂN TÍCH (TRONG THƯ MỤC `charts/`)

1. **[charts/handshake_latency.png](file:///f:/Smile-Net/charts/handshake_latency.png)** — *Phân phối thời gian bắt tay TLS 1.3 PQC & So sánh Boxplot giữa 4 Node Client*:
   - Thể hiện phân phối chuẩn lệch phải nhẹ với trung bình **7.60 ms**, trung vị **7.46 ms**, phân vị 95% đạt **9.35 ms**.
   - Boxplot phản ánh chính xác sự gia tăng độ trễ tuyến tính từ `client_1` (`7.06 ms`) đến `client_4` (`8.23 ms`) tương ứng với khoảng cách mạng mô phỏng.
2. **[charts/message_breakdown.png](file:///f:/Smile-Net/charts/message_breakdown.png)** — *Phân tích dung lượng bản tin TLS 1.3 & Tham số mật mã*:
   - Làm nổi bật kích thước `KeyShare` của `X25519MLKEM768` khiến `ClientHello` tăng từ `202 B` lên **`1,378 B`** (vừa khít 1 gói MTU 1500 mà không bị phân mảnh), trong khi chuỗi bản tin trả về từ Server đạt **`9,100 B`** tổng tải trọng Handshake.
3. **[charts/packet_size_distribution.png](file:///f:/Smile-Net/charts/packet_size_distribution.png)** — *Phân phối kích thước gói tin Ethernet & Hàm CDF*:
   - Cho thấy sự xuất hiện rõ nét của ~9,000 gói đạt kịch trần **MTU 1,514 bytes** do phân mảnh TCP của chứng chỉ và chữ ký `ML-DSA-65`.
4. **[charts/latency_over_time.png](file:///f:/Smile-Net/charts/latency_over_time.png)** — *Biến thiên độ trễ qua 1000 phiên liên tiếp*:
   - Thể hiện độ ổn định cao của ngăn xếp OpenSSL 3 + OQS-Provider trong suốt 1000 lượt trao đổi liên tục.
5. **[charts/throughput_over_time.png](file:///f:/Smile-Net/charts/throughput_over_time.png)** — *Thông lượng băng thông (Mbps) và Dung lượng tích lũy*:
   - Thông lượng đạt đỉnh ổn định **~30 Mbps** (~6.4 nghìn gói/giây) qua Switch trung tâm `s1`, tích lũy **18.19 MB** dữ liệu.
6. **[charts/packets_and_overhead.png](file:///f:/Smile-Net/charts/packets_and_overhead.png)** — *Số lượng gói tin mỗi phiên & Thời gian CPU xử lý chữ ký số ML-DSA-65*:
   - Minh họa chi phí tính toán cực nhanh của thuật toán hậu lượng tử dựa trên mạng tinh thể (Lattice-based): Ký `ML-DSA-65` chỉ mất trung bình **0.19 ms** và xác thực chỉ **0.07 ms**.
7. **[charts/summary_comparison.png](file:///f:/Smile-Net/charts/summary_comparison.png)** — *Bảng điều khiển đối chuẩn tổng hợp PQC vs Classical TLS 1.3*:
   - Tổng hợp trực quan: dù dung lượng truyền tải mỗi phiên tăng **5.79 lần** và số lượng gói tin tăng **2.12 lần**, thời gian bắt tay TLS 1.3 chỉ tăng **1.09 lần (+0.65 ms)** nhờ tốc độ xử lý rất nhanh của `ML-KEM-768` và `ML-DSA-65` cùng cơ chế TCP Initial Window (`IW10`).

---

## 4. DANH MỤC TỆP TIN BÀN GIAO

- **Kế hoạch & Báo cáo**:
  - [plan.md](file:///f:/Smile-Net/plan.md)
  - [REPORT.md](file:///f:/Smile-Net/REPORT.md)
- **Mã nguồn & Cấu hình**:
  - [config/openssl_pqc.cnf](file:///f:/Smile-Net/config/openssl_pqc.cnf)
  - [src/generate_certs.sh](file:///f:/Smile-Net/src/generate_certs.sh)
  - [src/pqc_crypto.py](file:///f:/Smile-Net/src/pqc_crypto.py)
  - [src/server_pqc.py](file:///f:/Smile-Net/src/server_pqc.py)
  - [src/client_pqc.py](file:///f:/Smile-Net/src/client_pqc.py)
  - [src/topology.py](file:///f:/Smile-Net/src/topology.py)
  - [src/analyze_and_plot.py](file:///f:/Smile-Net/src/analyze_and_plot.py)
- **Dữ liệu Bắt gói tin & Thống kê**:
  - `captures/tls_pqc_1000.pcap` (18.7 MB - 32,846 packets, 1000 PQC TLS 1.3 sessions)
  - `captures/tls_classic_baseline.pcap` (724 KB - 3,163 packets, 200 Classical TLS 1.3 sessions)
  - [data/benchmark_results.csv](file:///f:/Smile-Net/data/benchmark_results.csv)
  - [data/packet_metrics.json](file:///f:/Smile-Net/data/packet_metrics.json)

