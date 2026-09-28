# Secure Chat — E2EE, bản 5

Chat cá nhân/nhóm realtime, gửi ảnh, lịch sử, lựa chọn AES/DES. Tin mới được mã hóa và giải mã trên trình duyệt. Backend không nhận khóa giải mã dạng rõ, không giải mã tin và không lưu decryptedText/image dạng rõ.

## Chạy trên Windows

1. Giải nén vào thư mục mới và mở thư mục có package.json bằng VS Code.
2. Dừng server cũ bằng Ctrl+C. Chép .env đang kết nối Atlas thành công vào cạnh package.json.
3. Trong Terminal chạy:

```powershell
npm.cmd install
npm.cmd start
```

4. Mở http://localhost:8080 và Ctrl+F5. Không dùng Live Server.
5. Đăng nhập để mở kho khóa trên thiết bị. Mỗi lần tải lại trang cần nhập mật khẩu để mở khóa, dù cookie phiên còn hiệu lực.
6. Dùng Chrome và cửa sổ ẩn danh/Edge cho hai tài khoản. Mở cùng cuộc trò chuyện, chọn AES-GCM rồi gửi tin.
7. Bấm **Mã an toàn**, đối chiếu mã từng tài khoản với người đó qua gặp mặt hoặc kênh tin cậy. Mã phải giống trên cả hai thiết bị.

Node.js >=24. File .env là cấu hình, không dán các dòng đó vào Terminal:

```dotenv
MONGODB_URI=mongodb+srv://TEN_USER:MAT_KHAU@TEN_CLUSTER.mongodb.net/?appName=Cluster0
MONGODB_DB=secure_chat
PORT=8080
```

MESSAGE_ALGORITHM từ bản cũ không còn tác dụng. Chọn thuật toán trên giao diện. Người nhận tự giải mã theo thuật toán từng tin, không cần chọn giống người gửi.

## Dữ liệu cũ và tài khoản

Tài khoản bản v4 dùng lại được nếu vault và publicJwk còn nguyên và bạn biết mật khẩu. Không tạo khóa mới thay thế khóa cũ để đọc lịch sử. Mất mật khẩu hoặc mất vault/khóa thì không có chức năng khôi phục tin E2EE trong bản này.

**Tin cũ đã lưu bản rõ vẫn còn nguyên trong database cũ.** Bản mới không tự xóa/chuyển đổi những dữ liệu đó và không thể biến việc đã lộ bản rõ trước đây thành E2EE. Giao diện chỉ hiện thông báo cho tin cũ, không trả bản rõ qua API. Tin mới mới áp dụng E2EE. Không chạy lại server bản cũ để gửi tin vào cùng database.

Nếu muốn thử database hoàn toàn mới, đổi MONGODB_DB trong .env thành secure_chat_e2ee rồi khởi động lại và đăng ký tài khoản mới. Việc này không xóa database cũ.

## Xem MongoDB

Trong database được chỉ định bởi MONGODB_DB, collection messages:

| Trường | Nội dung |
|---|---|
| securityMode | E2EE-AES hoặc E2EE-DES-DEMO |
| algorithm | AES-GCM hoặc DES-CBC |
| packet.envelope.ciphertext | Bản mã của cả nội dung và ảnh |
| packet.envelope.iv | IV ngẫu nhiên |
| packet.envelope.mac | HMAC-SHA256 khi dùng DES |
| packet.wrappedKeys | Khóa tin đã mã hóa riêng cho từng thành viên, gồm cả người gửi |
| packet.recipients | ID thành viên có quyền mở tin |
| sender, recipient, conversation, createdAt | Metadata định tuyến và thời gian |

**Không có decryptedText, image bản rõ hay archiveKey trong tin mới.** Muốn đọc nội dung, đăng nhập trên ứng dụng. MongoDB không còn nơi để xem nội dung đã giải mã. Username, nhóm, thành viên, thời gian và trạng thái online vẫn là metadata nhìn thấy được ở server.

## Cơ chế

- Thiết bị tạo khóa ECDH P-256. Khóa riêng được mã hóa bằng AES-GCM với khóa từ mật khẩu qua PBKDF2-SHA256 (310.000 vòng), lưu vault mã hóa trên server. Mật khẩu không gửi lên server; đăng nhập dùng proof riêng.
- Khi gửi, thiết bị tạo khóa tin ngẫu nhiên, mã hóa JSON text/image với AES-256-GCM (mặc định) hoặc DES-CBC + HMAC-SHA256 (minh họa).
- ECDH + HKDF-SHA256 tạo khóa AES-GCM để bọc khóa tin riêng cho mỗi thành viên. Thông tin bản mã, người gửi, người nhận và danh sách thành viên được ràng buộc vào xác thực khi bọc khóa.
- Request, response, SSE và MongoDB chỉ chứa packet mã hóa cùng metadata. Backend xác thực phiên/thành viên/schema, không có mã giải mã tin. API lưu bản rõ cũ trả HTTP 410.
- Trình duyệt dùng khóa riêng mở khóa tin, kiểm tra toàn vẹn rồi hiển thị nội dung. Lịch sử tải lại được giải mã ở thiết bị sau đăng nhập.
- Ghim fingerprint khóa công khai theo lần dùng đầu tiên trên trình duyệt; khóa thay đổi sẽ bị chặn. Cần đối chiếu mã an toàn độc lập để xác minh lần đầu. Xóa dữ liệu trình duyệt làm mất bản ghim, cần đối chiếu lại.

API nền tảng: https://www.w3.org/TR/WebCryptoAPI/

## Giới hạn

Đây là bản đồ án E2EE, chưa kiểm toán bảo mật độc lập và không phải giao thức Signal. Dùng AES cho tin cần bảo mật; DES có khóa 56 bit, chỉ để minh họa thuật toán, không đủ an toàn cho dữ liệu thực tế.

Không có forward secrecy/ratchet: nếu khóa riêng bị lộ sau này, lịch sử liên quan có thể bị giải mã. Vault dùng mật khẩu nên cần mật khẩu mạnh, riêng biệt. Máy chủ phân phối mã JavaScript vẫn là điểm tin cậy; máy chủ bị chiếm quyền có thể phát mã độc để lấy khóa ở lần tải trang sau. E2EE không bảo vệ thiết bị bị chiếm quyền, XSS hoặc người nhận chụp/chuyển tiếp nội dung.

Bản này chạy localhost trên một máy. Triển khai Internet cần HTTPS, quản lý phiên bền vững, chỉnh Host/origin và rà soát bảo mật. HTTPS vẫn cần dù đã có E2EE. Nhóm có 3–30 thành viên cố định; chưa có thay đổi thành viên, đổi mật khẩu/khóa, xác nhận đã đọc hay cuộc gọi.

## Kiểm tra

```powershell
npm.cmd test
```

Đã đạt kiểm tra tích hợp với kho RAM: AES/DES, cá nhân/nhóm, người ngoài không mở được, sai khóa/bản mã sửa bị từ chối tại thiết bị, request/SSE/history/database không có bản rõ, bỏ API cũ, khởi động lại và đăng nhập lại mở được lịch sử. Chưa chạy Atlas thật hoặc xác nhận trực quan trong trình duyệt.

Bộ kiểm tra trình duyệt được cung cấp để chạy khi có Playwright/Chromium:

```powershell
npm.cmd install --no-save playwright
npx.cmd playwright install chromium
npm.cmd run test:browser
```
