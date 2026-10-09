# MultiMTR

![Downloads](https://img.shields.io/github/downloads/terminator3voz/MultiMTR/total)

**WinMTR-style network diagnostic tool that monitors multiple hosts at the same time.**
Traceroute + continuous ping with per-hop loss and latency statistics, a live latency graph and a simple Tkinter GUI. Pure Python, no third-party packages.

**Công cụ chẩn đoán mạng kiểu WinMTR, theo dõi nhiều host cùng lúc.** Traceroute và ping liên tục, thống kê loss/độ trễ từng hop, có đồ thị trực tiếp. Viết bằng Python thuần, không cần cài thêm thư viện.

---

## Tính năng

- Theo dõi **nhiều host đồng thời**, mỗi host chạy một luồng riêng và các hop được ping song song.
- Bảng chi tiết từng hop giống WinMTR: `Nr`, `Hostname`, `Loss %`, `Sent`, `Recv`, `Best`, `Avrg`, `Wrst`, `Last`.
- Bảng tóm tắt tất cả host: IP, trạng thái, số hop, loss, avg, worst, last của hop đích.
- Đồ thị độ trễ của hop đích (300 mẫu gần nhất), mất gói hiện bằng vạch đỏ.
- Tô màu hop mất gói (vàng khi có loss, đỏ từ 5% trở lên).
- Phân giải tên ngược (DNS) chạy nền, bật/tắt được.
- Chạy, dừng, xóa, trace lại cho từng host hoặc tất cả.
- **Copy text** báo cáo và **Xuất CSV**.
- Chu kỳ, timeout, kích thước gói, max hops chỉnh được ngay khi đang chạy.
- Tự lưu danh sách host và cấu hình vào `multimtr.json` khi đóng app.

## Tải về (Windows)

Tải `MultiMTR.exe` ở trang [Releases](https://github.com/terminator3voz/MultiMTR/releases/latest) rồi chạy, không cần cài đặt và **không cần quyền Administrator**.

> **Lưu ý:** file exe đóng gói bằng PyInstaller chưa có chữ ký số, nên Windows SmartScreen hoặc phần mềm diệt virus có thể cảnh báo. Nếu bạn không yên tâm, hãy chạy từ mã nguồn hoặc tự build theo hướng dẫn bên dưới.

## Chạy từ mã nguồn

Yêu cầu: Python 3.8 trở lên, có Tkinter (đi kèm bản Python cài từ python.org trên Windows).

```
python MultiMTR.py
```

| Hệ điều hành | Cách hoạt động | Quyền |
|---|---|---|
| Windows | Dùng `IcmpSendEcho` của `iphlpapi` | Không cần Administrator |
| Linux / macOS | Dùng raw ICMP socket | Cần chạy bằng `sudo` |

Trên Linux có thể cần cài Tkinter: `sudo apt install python3-tk`.

## Tự build file exe

```
pip install pyinstaller
pyinstaller --noconsole --onefile MultiMTR.py
```

File tạo ra nằm ở `dist\MultiMTR.exe`.

## Hướng dẫn sử dụng

1. Nhập host hoặc IP vào ô **Host / IP**, nhiều host cách nhau bằng dấu cách hoặc dấu phẩy, rồi bấm **Thêm** (hoặc Enter). Host mới thêm sẽ tự chạy.
2. Bấm vào một dòng ở bảng trên để xem chi tiết từng hop và đồ thị của host đó.
3. Dùng các nút **Chạy / Dừng / Reset / Xóa** cho host đang chọn hoặc tất cả.
4. Bấm **Copy text** hoặc **Xuất CSV** để lưu kết quả.

Danh sách host mặc định (khi chưa có `multimtr.json`): `192.168.1.1`, `203.113.131.1`, `youtube.com`, `google.com`, `facebook.com`, `voz.vn`. Bạn sửa ở biến `DEFAULT_HOSTS` trong mã nguồn.

### Cấu hình

File `multimtr.json` nằm **cùng thư mục với file `.py` hoặc `.exe`**, được ghi khi bạn đóng app bình thường:

```json
{
  "cfg": { "interval": 1000, "timeout": 1000, "size": 32, "maxhops": 30 },
  "dns": true,
  "hosts": ["192.168.1.1", "google.com"]
}
```

- `interval`: chu kỳ giữa các lượt ping (ms).
- `timeout`: thời gian chờ mỗi gói (ms).
- `size`: kích thước dữ liệu mỗi gói (byte).
- `maxhops`: số hop tối đa khi dò đường.

Nếu để exe ở thư mục không có quyền ghi (ví dụ `C:\Program Files`), cấu hình sẽ không được lưu.

## Cách đọc kết quả

- Nhìn **hop cuối (đích)** trước. Đích 0% loss và Worst không quá cao thì kết nối ổn.
- Loss chỉ ở một hop giữa, các hop sau và đích vẫn 0%: thường là router **giới hạn tốc độ trả lời ICMP**, không ảnh hưởng đến bạn.
- Loss bắt đầu ở một hop rồi kéo dài sang các hop sau đến cả đích: đó là mất gói thật, và hop đầu tiên bị loss là vị trí nghi ngờ.
- Hop hiện `No response from host`: thiết bị đó không trả lời ICMP, bình thường nếu các hop sau vẫn thông.
- Avg gần Best nghĩa là jitter thấp. Worst cao hơn hẳn Avg thì game hoặc cuộc gọi vẫn có thể giật dù loss bằng 0.
- Công cụ dùng ICMP và chỉ thấy chiều đi. Nếu lag chỉ xảy ra vào giờ cao điểm thì nên đo lại vào đúng giờ đó và đo lâu hơn.

## Giấy phép

MIT License, xem file [LICENSE](LICENSE).

## Tác giả

MultiMTR by Terminator3 @ voz.vn
