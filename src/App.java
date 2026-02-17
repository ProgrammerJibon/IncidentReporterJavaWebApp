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
                        sendResponse(t, renderLogin(null));
                    else
                        handleLogin(t);
                } else if (path.equals("/register")) {
                    if (method.equals("GET"))
                        sendResponse(t, renderRegister(null));
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
                        sendResponse(t, renderError("Account Banned. Contact Admin."));
                        return;
                    }

                    if (path.equals("/")) {
                        if (user.role.equals("admin"))
                            sendResponse(t, renderAdminDashboard(user));
                        else
                            sendResponse(t, renderStudentDashboard(user));
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
                sendResponse(t, renderLogin("Invalid Credentials"));
            }
        } catch (SQLException e) {
            e.printStackTrace();
            sendResponse(t, renderError("Database Error"));
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
            sendResponse(t, renderRegister("Username taken"));
        } catch (SQLException e) {
            e.printStackTrace();
            sendResponse(t, renderError("Database Error"));
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
            sendResponse(t, renderError("Database Error"));
        }
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

    private static String getHead() {
        return "<html><head><title>Incident Report</title>" +
                "<script src='https://cdn.tailwindcss.com'></script>" +
                "<meta charset='UTF-8'></head><body class='bg-gray-100 font-sans'>";
    }

    private static String renderLogin(String err) {
        return getHead() + "<div class='min-h-screen flex items-center justify-center'>" +
                "<div class='bg-white p-8 rounded shadow-md w-96'>" +
                "<h1 class='text-2xl font-bold mb-4 text-center'>Login</h1>" +
                (err != null ? "<p class='text-red-500 text-sm mb-4'>" + err + "</p>" : "") +
                "<form method='POST' action='/login'>" +
                "<input name='username' placeholder='Username' class='w-full border p-2 mb-2 rounded' required>" +
                "<input type='password' name='password' placeholder='Password' class='w-full border p-2 mb-4 rounded' required>"
                +
                "<button class='w-full bg-blue-600 text-white p-2 rounded hover:bg-blue-700'>Login</button>" +
                "</form><div class='mt-4 text-center'><a href='/register' class='text-blue-500 text-sm'>Create Account</a></div><div class='mt-4 text-center text-xs text-gray-400'>Build by Nujhat Arfa</div></div></div></body></html>";
    }

    private static String renderRegister(String err) {
        return getHead() + "<div class='min-h-screen flex items-center justify-center'>" +
                "<div class='bg-white p-8 rounded shadow-md w-96'>" +
                "<h1 class='text-2xl font-bold mb-4 text-center'>Register</h1>" +
                (err != null ? "<p class='text-red-500 text-sm mb-4'>" + err + "</p>" : "") +
                "<form method='POST' action='/register'>" +
                "<input name='username' placeholder='Username' class='w-full border p-2 mb-2 rounded' required>" +
                "<input type='password' name='password' placeholder='Password' class='w-full border p-2 mb-4 rounded' required>"
                +
                "<button class='w-full bg-green-600 text-white p-2 rounded hover:bg-green-700'>Register</button>" +
                "</form><div class='mt-4 text-center'><a href='/login' class='text-blue-500 text-sm'>Back to Login</a></div></div></div></body></html>";
    }

    private static String renderStudentDashboard(User u) {
        StringBuilder html = new StringBuilder(getHead());
        html.append(nav(u));
        html.append("<div class='container mx-auto p-6 grid grid-cols-1 md:grid-cols-3 gap-6'>");

        html.append("<div class='md:col-span-1 bg-white p-6 rounded shadow'>");
        html.append("<h2 class='text-xl font-bold mb-4'>New Incident</h2>");
        html.append("<form method='POST' action='/report' enctype='multipart/form-data'>");
        html.append(
                "<textarea name='description' placeholder='Describe what happened...' class='w-full border p-2 mb-2 rounded' rows='4' required></textarea>");
        html.append(
                "<input name='location' placeholder='Location (e.g. Lab 201)' class='w-full border p-2 mb-2 rounded' required>");
        html.append("<label class='block mb-2 text-sm text-gray-600'>Attach Image:</label>");
        html.append("<input type='file' name='image' class='w-full mb-4'>");
        html.append(
                "<div class='flex items-center mb-4'><input type='checkbox' name='anonymous' class='mr-2'> Report Anonymously</div>");
        html.append("<button class='w-full bg-indigo-600 text-white p-2 rounded'>Submit Report</button></form></div>");

        html.append("<div class='md:col-span-2 space-y-4'>");
        html.append("<h2 class='text-xl font-bold'>My Reports</h2>");

        List<Report> myReports = new ArrayList<>();
        try (Connection conn = getConn();
                PreparedStatement ps = conn
                        .prepareStatement("SELECT * FROM reports WHERE user_id=? ORDER BY created_at DESC")) {
            ps.setInt(1, u.id);
            ResultSet rs = ps.executeQuery();
            while (rs.next()) {
                myReports.add(new Report(rs.getInt("id"), rs.getInt("user_id"), rs.getString("description"),
                        rs.getString("location"), rs.getString("image_path"), rs.getString("status"),
                        rs.getString("priority"), rs.getBoolean("is_anonymous"), rs.getString("created_at")));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }

        for (Report r : myReports)
            html.append(renderReportCard(r, false));
        html.append("</div></div></body></html>");
        return html.toString();
    }

    private static String renderAdminDashboard(User u) {
        StringBuilder html = new StringBuilder(getHead());
        html.append(nav(u));
        html.append("<div class='container mx-auto p-6'>");

        html.append("<div class='mb-8'><h2 class='text-xl font-bold mb-4'>User Management</h2>");
        html.append(
                "<div class='bg-white rounded shadow overflow-x-auto'><table class='w-full text-left border-collapse'>");
        html.append(
                "<thead><tr class='bg-gray-200'><th class='p-3'>ID</th><th class='p-3'>Username</th><th class='p-3'>Role</th><th class='p-3'>Status</th><th class='p-3'>Actions</th></tr></thead><tbody>");

        try (Connection conn = getConn();
                Statement stmt = conn.createStatement();
                ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE role != 'admin'")) {
            while (rs.next()) {
                int id = rs.getInt("id");
                boolean banned = rs.getBoolean("is_banned");
                String status = banned ? "<span class='text-red-500'>Banned</span>"
                        : "<span class='text-green-500'>Active</span>";

                html.append("<tr class='border-b'><td class='p-3'>").append(id).append("</td>");
                html.append("<td class='p-3'>").append(rs.getString("username")).append("</td>");
                html.append("<td class='p-3'>").append(rs.getString("role")).append("</td>");
                html.append("<td class='p-3'>").append(status).append("</td>");
                html.append("<td class='p-3 flex gap-2'>");

                if (!banned)
                    html.append("<form method='POST' action='/admin/users'><input type='hidden' name='id' value='" + id
                            + "'><input type='hidden' name='action' value='ban'><button class='text-xs bg-red-500 text-white px-2 py-1 rounded'>Ban</button></form>");
                else
                    html.append("<form method='POST' action='/admin/users'><input type='hidden' name='id' value='" + id
                            + "'><input type='hidden' name='action' value='unban'><button class='text-xs bg-green-500 text-white px-2 py-1 rounded'>Unban</button></form>");

                html.append("<form method='POST' action='/admin/users'><input type='hidden' name='id' value='" + id
                        + "'><input type='hidden' name='action' value='reset'><button class='text-xs bg-yellow-500 text-white px-2 py-1 rounded'>Reset Pass</button></form>");
                html.append("</td></tr>");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        html.append("</tbody></table></div></div>");

        html.append(
                "<div><h2 class='text-xl font-bold mb-4'>Incident Reports</h2><div class='grid grid-cols-1 gap-4'>");

        try (Connection conn = getConn();
                Statement stmt = conn.createStatement();
                ResultSet rs = stmt.executeQuery("SELECT * FROM reports ORDER BY created_at DESC")) {
            while (rs.next()) {
                Report r = new Report(rs.getInt("id"), rs.getInt("user_id"), rs.getString("description"),
                        rs.getString("location"), rs.getString("image_path"), rs.getString("status"),
                        rs.getString("priority"), rs.getBoolean("is_anonymous"), rs.getString("created_at"));
                html.append(renderReportCard(r, true));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }

        html.append("</div></div></div></body></html>");
        return html.toString();
    }

    private static String renderReportCard(Report r, boolean isAdmin) {
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

        StringBuilder sb = new StringBuilder();
        sb.append("<div class='bg-white p-4 rounded shadow border-l-4 border-").append(color).append("-500'>");
        sb.append("<div class='flex justify-between mb-2'><span class='font-bold text-lg'>").append(reporter)
                .append("</span>");
        sb.append("<span class='text-sm text-gray-500'>").append(r.createdAt).append("</span></div>");
        sb.append("<p class='text-gray-700 mb-2'>").append(r.description).append("</p>");
        sb.append("<div class='text-sm text-gray-600 mb-2'>📍 ").append(r.location).append("</div>");
        if (r.imagePath != null)
            sb.append("<div class='mb-2'><a href='/").append(r.imagePath)
                    .append("' target='_blank' class='text-blue-500 text-sm underline'>View Attached Image</a></div>");

        sb.append("<div class='flex items-center justify-between mt-4 bg-gray-50 p-2 rounded'>");
        if (isAdmin) {
            sb.append("<form method='POST' action='/admin/update' class='flex gap-2 w-full items-center'>");
            sb.append("<input type='hidden' name='id' value='").append(r.id).append("'>");
            sb.append("<select name='priority' class='border p-1 rounded text-sm'><option>").append(r.priority).append(
                    "</option><option>Low</option><option>Normal</option><option>High</option><option>Critical</option></select>");
            sb.append("<select name='status' class='border p-1 rounded text-sm'><option>").append(r.status).append(
                    "</option><option>Pending</option><option>In Progress</option><option>Solved</option></select>");
            sb.append("<button class='bg-blue-600 text-white px-3 py-1 rounded text-sm'>Update</button></form>");
        } else {
            sb.append("<div>Status: <span class='font-bold text-").append(color).append("-600'>").append(r.status)
                    .append("</span></div>");
            sb.append("<div>Priority: <span class='font-bold'>").append(r.priority).append("</span></div>");
        }
        sb.append("</div></div>");
        return sb.toString();
    }

    private static String nav(User u) {
        return "<nav class='bg-gray-800 p-4 text-white flex justify-between shadow'>" +
                "<div class='font-bold'>🛡️ UGV Incident System</div>" +
                "<div class='flex gap-4 items-center'><span>Welcome, " + u.username + " (" + u.role + ")</span>" +
                "<a href='/logout' class='bg-red-600 px-3 py-1 rounded text-sm hover:bg-red-700'>Logout</a></div></nav>";
    }

    private static String renderError(String msg) {
        return "<html><body style='color:red; text-align:center; padding-top:50px;'><h1>Error</h1><p>" + msg
                + "</p></body></html>";
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