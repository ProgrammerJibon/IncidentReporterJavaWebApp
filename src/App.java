import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.sql.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class App {

    private static final int PORT = 3005;
    private static final String UPLOAD_DIR = "uploads";

    private static final String DB_URL = "jdbc:mysql://localhost:3306/";
    private static final String DB_NAME = "incident_db";
    private static final String DB_USER = "root";
    private static final String DB_PASS = "";

    public static void main(String[] args) throws IOException {
        initDatabase();

        HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);
        server.createContext("/", new Handler());
        server.setExecutor(null);
        System.out.println(">>> System Started: http://localhost:" + PORT);
        server.start();
    }

    private static Connection getConn() throws SQLException {
        return DriverManager.getConnection(DB_URL + DB_NAME, DB_USER, DB_PASS);
    }

    private static void initDatabase() {
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);
                Statement stmt = conn.createStatement()) {

            stmt.executeUpdate("CREATE DATABASE IF NOT EXISTS " + DB_NAME);
            stmt.executeUpdate("USE " + DB_NAME);

            String userTable = "CREATE TABLE IF NOT EXISTS users (" +
                    "id INT AUTO_INCREMENT PRIMARY KEY, " +
                    "username VARCHAR(50) UNIQUE, " +
                    "password VARCHAR(100), " +
                    "role VARCHAR(20), " +
                    "is_banned BOOLEAN DEFAULT FALSE)";
            stmt.executeUpdate(userTable);

            String reportTable = "CREATE TABLE IF NOT EXISTS reports (" +
                    "id INT AUTO_INCREMENT PRIMARY KEY, " +
                    "user_id INT, " +
                    "description TEXT, " +
                    "location VARCHAR(100), " +
                    "image_path VARCHAR(255), " +
                    "status VARCHAR(20) DEFAULT 'Pending', " +
                    "priority VARCHAR(20) DEFAULT 'Normal', " +
                    "is_anonymous BOOLEAN, " +
                    "created_at VARCHAR(30))";
            stmt.executeUpdate(reportTable);

            String sessionTable = "CREATE TABLE IF NOT EXISTS sessions (" +
                    "token VARCHAR(100) PRIMARY KEY, " +
                    "user_id INT, " +
                    "expiry_time BIGINT)";
            stmt.executeUpdate(sessionTable);

            try (ResultSet rs = stmt.executeQuery("SELECT count(*) FROM users WHERE username='admin'")) {
                if (rs.next() && rs.getInt(1) == 0) {
                    stmt.executeUpdate("INSERT INTO users (username, password, role) VALUES ('admin', '"
                            + hashPassword("12345678") + "', 'admin')");
                }
            }

        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    private static String loadTemplate(String filename) {
        try {
            return Files.readString(Paths.get("src/web/" + filename));
        } catch (IOException e) {
            e.printStackTrace();
            return "Error loading template: " + filename;
        }
    }

    static class User {
        int id;
        String username;
        String role;
        boolean isBanned;

        public User(int id, String username, String role, boolean isBanned) {
            this.id = id;
            this.username = username;
            this.role = role;
            this.isBanned = isBanned;
        }
    }

    static class Report {
        int id;
        int userId;
        String description;
        String location;
        String imagePath;
        String status;
        String priority;
        boolean isAnonymous;
        String createdAt;

        public Report(int id, int userId, String description, String location, String imagePath,
                String status, String priority, boolean isAnonymous, String createdAt) {
            this.id = id;
            this.userId = userId;
            this.description = description;
            this.location = location;
            this.imagePath = imagePath;
            this.status = status;
            this.priority = priority;
            this.isAnonymous = isAnonymous;
            this.createdAt = createdAt;
        }
    }

    static class Handler implements HttpHandler {
        @Override
        public void handle(HttpExchange t) throws IOException {
            String path = t.getRequestURI().getPath();
            String method = t.getRequestMethod();

            if (path.startsWith("/uploads/")) {
                serveFile(t, path);
                return;
            }

            User user = getAuthUser(t);

            try {
                if (path.equals("/login")) {
                    if (method.equals("GET"))
                        sendResponse(t, loadTemplate("login.html").replace("{{ERROR}}", ""));
                    else
                        handleLogin(t);
                } else if (path.equals("/register")) {
                    if (method.equals("GET"))
                        sendResponse(t, loadTemplate("register.html").replace("{{ERROR}}", ""));
                    else
                        handleRegister(t);
                } else if (path.equals("/logout")) {
                    handleLogout(t);
                } else {
                    if (user == null) {
                        redirect(t, "/login");
                        return;
                    }
                    if (user.isBanned) {
                        sendResponse(t,
                                loadTemplate("error.html").replace("{{MESSAGE}}", "Account Banned. Contact Admin."));
                        return;
                    }

                    if (path.equals("/")) {
                        if (user.role.equals("admin"))
                            handleAdminDashboard(t, user);
                        else
                            handleStudentDashboard(t, user);
                    } else if (path.equals("/report") && method.equals("POST")) {
                        handleReport(t, user);
                    } else if (path.equals("/admin/update") && user.role.equals("admin")) {
                        handleAdminUpdate(t);
                    } else if (path.equals("/admin/users") && user.role.equals("admin")) {
                        handleUserManage(t);
                    } else {
                        sendResponse(t, "404 Not Found");
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
                sendResponse(t, "Internal Error: " + e.getMessage());
            }
        }
    }

    private static void handleLogin(HttpExchange t) throws IOException {
        Map<String, String> params = parseFormData(t);
        String u = params.get("username");
        String p = hashPassword(params.get("password"));

        try (Connection conn = getConn();
                PreparedStatement ps = conn.prepareStatement("SELECT id FROM users WHERE username=? AND password=?")) {
            ps.setString(1, u);
            ps.setString(2, p);
            ResultSet rs = ps.executeQuery();

            if (rs.next()) {
                int userId = rs.getInt("id");
                String token = UUID.randomUUID().toString();
                try (PreparedStatement sessPs = conn
                        .prepareStatement("INSERT INTO sessions (token, user_id, expiry_time) VALUES (?, ?, ?)")) {
                    sessPs.setString(1, token);
                    sessPs.setInt(2, userId);
                    sessPs.setLong(3, System.currentTimeMillis() + (24 * 60 * 60 * 1000));
                    sessPs.executeUpdate();
                }
                t.getResponseHeaders().add("Set-Cookie", "auth=" + token + "; Path=/; HttpOnly");
                redirect(t, "/");
            } else {
                sendResponse(t, loadTemplate("login.html").replace("{{ERROR}}", "Invalid Credentials"));
            }
        } catch (SQLException e) {
            e.printStackTrace();
            sendResponse(t, loadTemplate("error.html").replace("{{MESSAGE}}", "Database Error"));
        }
    }

    private static void handleRegister(HttpExchange t) throws IOException {
        Map<String, String> params = parseFormData(t);
        String u = params.get("username");
        String p = hashPassword(params.get("password"));

        try (Connection conn = getConn();
                PreparedStatement ps = conn
                        .prepareStatement("INSERT INTO users (username, password, role) VALUES (?, ?, 'student')")) {
            ps.setString(1, u);
            ps.setString(2, p);
            ps.executeUpdate();
            redirect(t, "/login");
        } catch (SQLIntegrityConstraintViolationException e) {
            sendResponse(t, loadTemplate("register.html").replace("{{ERROR}}", "Username taken"));
        } catch (SQLException e) {
            e.printStackTrace();
            sendResponse(t, loadTemplate("error.html").replace("{{MESSAGE}}", "Database Error"));
        }
    }

    private static void handleReport(HttpExchange t, User user) throws IOException {
        Map<String, Object> parts = parseMultipart(t);
        String desc = (String) parts.get("description");
        String loc = (String) parts.get("location");
        boolean anon = parts.containsKey("anonymous");

        String imagePath = null;
        if (parts.containsKey("image") && parts.get("image") instanceof byte[]) {
            byte[] imgData = (byte[]) parts.get("image");
            String filename = (String) parts.get("image_name");
            if (imgData.length > 0) {
                LocalDateTime now = LocalDateTime.now();
                String folder = UPLOAD_DIR + "/" + user.id + "/" + now.getYear() + "/" + now.getMonthValue() + "/"
                        + now.getDayOfMonth();
                new File(folder).mkdirs();
                imagePath = folder + "/" + System.currentTimeMillis() + "_" + filename;
                Files.write(Paths.get(imagePath), imgData);
            }
        }

        try (Connection conn = getConn();
                PreparedStatement ps = conn.prepareStatement(
                        "INSERT INTO reports (user_id, description, location, image_path, is_anonymous, created_at) VALUES (?, ?, ?, ?, ?, ?)")) {
            ps.setInt(1, user.id);
            ps.setString(2, desc);
            ps.setString(3, loc);
            ps.setString(4, imagePath);
            ps.setBoolean(5, anon);
            ps.setString(6, LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")));
            ps.executeUpdate();
            redirect(t, "/");
        } catch (SQLException e) {
            e.printStackTrace();
            sendResponse(t, loadTemplate("error.html").replace("{{MESSAGE}}", "Database Error"));
        }
    }

    private static void handleStudentDashboard(HttpExchange t, User u) throws IOException {
        String html = loadTemplate("student_dashboard.html");
        html = html.replace("{{USERNAME}}", u.username);
        html = html.replace("{{ROLE}}", u.role);

        StringBuilder reportsHtml = new StringBuilder();
        try (Connection conn = getConn();
                PreparedStatement ps = conn
                        .prepareStatement("SELECT * FROM reports WHERE user_id=? ORDER BY created_at DESC")) {
            ps.setInt(1, u.id);
            ResultSet rs = ps.executeQuery();
            String cardTemplate = loadTemplate("report_card.html");
            while (rs.next()) {
                Report r = mapReport(rs);
                reportsHtml.append(processReportCard(r, cardTemplate, false));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        html = html.replace("{{REPORTS}}", reportsHtml.toString());
        sendResponse(t, html);
    }

    private static void handleAdminDashboard(HttpExchange t, User u) throws IOException {
        String html = loadTemplate("admin_dashboard.html");
        html = html.replace("{{USERNAME}}", u.username);
        html = html.replace("{{ROLE}}", u.role);

        StringBuilder usersHtml = new StringBuilder();
        try (Connection conn = getConn();
                Statement stmt = conn.createStatement();
                ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE role != 'admin'")) {
            String rowTemplate = loadTemplate("user_row.html");
            while (rs.next()) {
                int id = rs.getInt("id");
                String uname = rs.getString("username");
                String role = rs.getString("role");
                boolean banned = rs.getBoolean("is_banned");

                String row = rowTemplate.replace("{{ID}}", String.valueOf(id))
                        .replace("{{USERNAME}}", uname)
                        .replace("{{ROLE}}", role);

                if (banned) {
                    row = row.replace("{{STATUS_LABEL}}", "<span class='text-red-500'>Banned</span>");
                    row = row.replace("{{ACTIONS}}",
                            "<form method='POST' action='/admin/users'><input type='hidden' name='id' value='" + id
                                    + "'><input type='hidden' name='action' value='unban'><button class='text-xs bg-green-500 text-white px-2 py-1 rounded'>Unban</button></form>");
                } else {
                    row = row.replace("{{STATUS_LABEL}}", "<span class='text-green-500'>Active</span>");
                    row = row.replace("{{ACTIONS}}",
                            "<form method='POST' action='/admin/users'><input type='hidden' name='id' value='" + id
                                    + "'><input type='hidden' name='action' value='ban'><button class='text-xs bg-red-500 text-white px-2 py-1 rounded'>Ban</button></form>");
                }
                usersHtml.append(row);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        html = html.replace("{{USER_ROWS}}", usersHtml.toString());

        StringBuilder reportsHtml = new StringBuilder();
        try (Connection conn = getConn();
                Statement stmt = conn.createStatement();
                ResultSet rs = stmt.executeQuery("SELECT * FROM reports ORDER BY created_at DESC")) {
            String cardTemplate = loadTemplate("report_card.html");
            while (rs.next()) {
                Report r = mapReport(rs);
                reportsHtml.append(processReportCard(r, cardTemplate, true));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        html = html.replace("{{REPORTS}}", reportsHtml.toString());
        sendResponse(t, html);
    }

    private static Report mapReport(ResultSet rs) throws SQLException {
        return new Report(rs.getInt("id"), rs.getInt("user_id"), rs.getString("description"),
                rs.getString("location"), rs.getString("image_path"), rs.getString("status"),
                rs.getString("priority"), rs.getBoolean("is_anonymous"), rs.getString("created_at"));
    }

    private static String processReportCard(Report r, String template, boolean isAdmin) {
        String reporter = "Unknown";
        if (r.isAnonymous) {
            reporter = "Anonymous Student";
        } else {
            try (Connection conn = getConn();
                    PreparedStatement ps = conn.prepareStatement("SELECT username FROM users WHERE id=?")) {
                ps.setInt(1, r.userId);
                ResultSet rs = ps.executeQuery();
                if (rs.next())
                    reporter = rs.getString("username");
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }

        String color = r.status.equals("Pending") ? "yellow" : r.status.equals("Solved") ? "green" : "blue";
        String html = template.replace("{{COLOR}}", color)
                .replace("{{REPORTER}}", reporter)
                .replace("{{DATE}}", r.createdAt)
                .replace("{{DESCRIPTION}}", r.description)
                .replace("{{LOCATION}}", r.location);

        if (r.imagePath != null && !r.imagePath.isEmpty()) {
            html = html.replace("{{IMAGE_SECTION}}", "<div class='mb-2'><a href='/" + r.imagePath
                    + "' target='_blank' class='text-blue-500 text-sm underline'>View Attached Image</a></div>");
        } else {
            html = html.replace("{{IMAGE_SECTION}}", "");
        }

        if (isAdmin) {
            String form = "<form method='POST' action='/admin/update' class='flex gap-2 w-full items-center'>" +
                    "<input type='hidden' name='id' value='" + r.id + "'>" +
                    "<select name='priority' class='border p-1 rounded text-sm'><option>" + r.priority
                    + "</option><option>Low</option><option>Normal</option><option>High</option><option>Critical</option></select>"
                    +
                    "<select name='status' class='border p-1 rounded text-sm'><option>" + r.status
                    + "</option><option>Pending</option><option>In Progress</option><option>Solved</option></select>" +
                    "<button class='bg-blue-600 text-white px-3 py-1 rounded text-sm'>Update</button></form>";
            html = html.replace("{{CONTROLS}}", form);
        } else {
            String status = "<div>Status: <span class='font-bold text-" + color + "-600'>" + r.status + "</span></div>"
                    +
                    "<div>Priority: <span class='font-bold'>" + r.priority + "</span></div>";
            html = html.replace("{{CONTROLS}}", status);
        }
        return html;
    }

    private static void handleAdminUpdate(HttpExchange t) throws IOException {
        Map<String, String> params = parseFormData(t);
        try (Connection conn = getConn();
                PreparedStatement ps = conn.prepareStatement("UPDATE reports SET status=?, priority=? WHERE id=?")) {
            ps.setString(1, params.get("status"));
            ps.setString(2, params.get("priority"));
            ps.setInt(3, Integer.parseInt(params.get("id")));
            ps.executeUpdate();
            redirect(t, "/");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    private static void handleUserManage(HttpExchange t) throws IOException {
        Map<String, String> params = parseFormData(t);
        int uId = Integer.parseInt(params.get("id"));
        String action = params.get("action");

        try (Connection conn = getConn()) {
            if ("ban".equals(action)) {
                try (PreparedStatement ps = conn.prepareStatement("UPDATE users SET is_banned=TRUE WHERE id=?")) {
                    ps.setInt(1, uId);
                    ps.executeUpdate();
                }
            } else if ("unban".equals(action)) {
                try (PreparedStatement ps = conn.prepareStatement("UPDATE users SET is_banned=FALSE WHERE id=?")) {
                    ps.setInt(1, uId);
                    ps.executeUpdate();
                }
            } else if ("reset".equals(action)) {
                try (PreparedStatement ps = conn.prepareStatement("UPDATE users SET password=? WHERE id=?")) {
                    ps.setString(1, hashPassword("12345678"));
                    ps.setInt(2, uId);
                    ps.executeUpdate();
                }
            }
            redirect(t, "/");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    private static void handleLogout(HttpExchange t) throws IOException {
        String cookie = t.getRequestHeaders().getFirst("Cookie");
        if (cookie != null && cookie.contains("auth=")) {
            String token = cookie.split("auth=")[1].split(";")[0];
            try (Connection conn = getConn();
                    PreparedStatement ps = conn.prepareStatement("DELETE FROM sessions WHERE token=?")) {
                ps.setString(1, token);
                ps.executeUpdate();
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
        t.getResponseHeaders().add("Set-Cookie", "auth=; Path=/; Max-Age=0");
        redirect(t, "/login");
    }

    private static User getAuthUser(HttpExchange t) {
        String cookie = t.getRequestHeaders().getFirst("Cookie");
        if (cookie == null || !cookie.contains("auth="))
            return null;
        String token = cookie.split("auth=")[1].split(";")[0];

        try (Connection conn = getConn();
                PreparedStatement ps = conn.prepareStatement(
                        "SELECT u.id, u.username, u.role, u.is_banned, s.expiry_time " +
                                "FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.token = ?")) {
            ps.setString(1, token);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) {
                if (rs.getLong("expiry_time") < System.currentTimeMillis())
                    return null;
                return new User(rs.getInt("id"), rs.getString("username"), rs.getString("role"),
                        rs.getBoolean("is_banned"));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static String hashPassword(String p) {
        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            byte[] s1 = sha1.digest(p.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb1 = new StringBuilder();
            for (byte b : s1)
                sb1.append(String.format("%02x", b));
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            byte[] s2 = md5.digest(sb1.toString().getBytes(StandardCharsets.UTF_8));
            StringBuilder sb2 = new StringBuilder();
            for (byte b : s2)
                sb2.append(String.format("%02x", b));
            return sb2.toString();
        } catch (Exception e) {
            return p;
        }
    }

    private static void sendResponse(HttpExchange t, String response) throws IOException {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        t.sendResponseHeaders(200, bytes.length);
        OutputStream os = t.getResponseBody();
        os.write(bytes);
        os.close();
    }

    private static void redirect(HttpExchange t, String loc) throws IOException {
        t.getResponseHeaders().set("Location", loc);
        t.sendResponseHeaders(302, -1);
    }

    private static void serveFile(HttpExchange t, String path) throws IOException {
        File file = new File("." + path);
        if (file.exists() && !file.isDirectory()) {
            t.sendResponseHeaders(200, file.length());
            Files.copy(file.toPath(), t.getResponseBody());
            t.getResponseBody().close();
        } else {
            sendResponse(t, "File not found");
        }
    }

    private static Map<String, String> parseFormData(HttpExchange t) throws IOException {
        Map<String, String> params = new HashMap<>();
        InputStreamReader isr = new InputStreamReader(t.getRequestBody(), StandardCharsets.UTF_8);
        BufferedReader br = new BufferedReader(isr);
        String query = br.readLine();
        if (query != null) {
            for (String pair : query.split("&")) {
                String[] kv = pair.split("=");
                if (kv.length > 1)
                    params.put(URLDecoder.decode(kv[0], "UTF-8"), URLDecoder.decode(kv[1], "UTF-8"));
            }
        }
        return params;
    }

    private static Map<String, Object> parseMultipart(HttpExchange t) throws IOException {
        Map<String, Object> res = new HashMap<>();
        String boundary = t.getRequestHeaders().getFirst("Content-Type").split("boundary=")[1];
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        InputStream is = t.getRequestBody();
        byte[] data = new byte[1024];
        int nRead;
        while ((nRead = is.read(data, 0, data.length)) != -1)
            buffer.write(data, 0, nRead);
        byte[] body = buffer.toByteArray();

        String bodyStr = new String(body, StandardCharsets.ISO_8859_1);
        String[] parts = bodyStr.split("--" + boundary);

        for (String part : parts) {
            if (part.contains("name=\"description\""))
                res.put("description", extractVal(part));
            else if (part.contains("name=\"location\""))
                res.put("location", extractVal(part));
            else if (part.contains("name=\"anonymous\""))
                res.put("anonymous", true);
            else if (part.contains("filename=\"")) {
                String filename = part.substring(part.indexOf("filename=\"") + 10);
                filename = filename.substring(0, filename.indexOf("\""));
                res.put("image_name", filename);

                int headerEnd = part.indexOf("\r\n\r\n") + 4;
                int dataEnd = part.lastIndexOf("\r\n");
                if (headerEnd < dataEnd) {
                    String rawData = part.substring(headerEnd, dataEnd);
                    res.put("image", rawData.getBytes(StandardCharsets.ISO_8859_1));
                }
            }
        }
        return res;
    }

    private static String extractVal(String part) {
        int start = part.indexOf("\r\n\r\n") + 4;
        int end = part.lastIndexOf("\r\n");
        return (start < end) ? part.substring(start, end).trim() : "";
    }
}