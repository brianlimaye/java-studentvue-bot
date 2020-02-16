package ssc;

import org.jsoup.Jsoup;
import org.jsoup.nodes.*;

import javax.mail.Message;
import javax.mail.Multipart;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.*;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import org.apache.commons.lang3.StringUtils;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.*;

public class Main {

    private final static String VIEWSTATE_KEY = "__VIEWSTATE";
    private final static String VIEWSTATE_GENERATOR_KEY = "__VIEWSTATEGENERATOR";
    private final static String EVENTVALIDATION_KEY = "__EVENTVALIDATION";
    private final static String USERNAME = "ctl00%24MainContent%24username";
    private final static String PASSWORD = "ctl00%24MainContent%24password";

    private final static String VALID_AUTHENTICATED_ASSERTION = "ST.Authorization = {\"access_token\":\"authorized\"};";

    private final String lcpsUserName;
    private final String lcpsPassword;

    public Main(final String lcpsUserName, final String lcpsPassword) {
        this.lcpsUserName = lcpsUserName;
        this.lcpsPassword = lcpsPassword;
    }

    public static void main(String[] args) throws Throwable {

        String smtpHost = null;
        int smtpPort = -1;
        String smtpUserName = null;
        String smtpPassword = null;
        String smtpTo = null;
        String smtpFrom = null;
        String lcpsUserName = null;
        String lcpsPassword = null;

        for (int i = 0; i < args.length; i++) {
            try {
                if (args[i].equalsIgnoreCase("--smtpHost")) {
                    smtpHost = args[++i];
                } else if (args[i].equalsIgnoreCase("--smtpPort")) {
                    smtpPort = Integer.parseInt(args[++i]);
                } else if (args[i].equalsIgnoreCase("--smtpUserName")) {
                    smtpUserName = args[++i];
                } else if (args[i].equalsIgnoreCase(("--smtpPassword"))) {
                    smtpPassword = args[++i];
                } else if (args[i].equalsIgnoreCase("--smtpTo")) {
                    smtpTo = args[++i];
                } else if (args[i].equalsIgnoreCase("--smtpFrom")) {
                    smtpFrom = args[++i];
                } else if (args[i].equalsIgnoreCase("--lcpsUserName")) {
                    lcpsUserName = args[++i];
                } else if (args[i].equalsIgnoreCase("--lcpsPassword")) {
                    lcpsPassword = args[++i];
                }
            } catch (Throwable t) {
                usage();
            }
        }

        if (isEmpty(new String[]{smtpHost, smtpUserName, smtpPassword, smtpTo, smtpFrom, lcpsUserName, lcpsPassword})) {
            usage();
        }

        if ((smtpPort < 1) || (smtpPort > 65535)) {
            usage();
        }

        System.out.println("<SMTP HOST>: " + smtpHost);
        System.out.println("<SMTP PORT>: " + smtpPort);
        System.out.println("<SMTP USERNAME>: " + smtpUserName);
        System.out.println("<SMTP PASSWORD>: " + "******");
        System.out.println("<SMTP TO>: " + smtpTo);
        System.out.println("<SMTP FROM>: " + smtpFrom);
        System.out.println("<LCPS USERNAME>: " + lcpsUserName);
        System.out.println("<LCPS PASSWORD>: " + "******");

        final Timer timer = new Timer(); // Instantiate Timer Object
        final ScheduledTask scheduledTask = new ScheduledTask(smtpHost, smtpPort, smtpUserName, smtpPassword, smtpTo, smtpFrom, lcpsUserName, lcpsPassword);
        timer.schedule(scheduledTask, 0, (60 * 10) * 1000); // every 10 minutes
    }

    private static void usage() {
        System.err.println("java -jar StudentVue-1.0-SNAPSHOT-jar-with-dependencies.jar --smtpHost <host> --smtpPort <port> --smtpUserName <userName> --smtpPassword <password> --smtpTo <to> --smtpFrom <from> --lcpsUserName <username> --lcpsPassword <password>");
        System.exit(1);
    }

    private static boolean isEmpty(final String[] arr) {
        if (arr == null) {
            return true;
        }

        if (arr.length == 0) {
            return true;
        }

        for (int i = 0; i < arr.length; i++) {
            if (isEmpty(arr[i])) {
                return true;
            }
        }

        return false;
    }

    private static boolean isEmpty(final String str)
    {
        return StringUtils.isEmpty(str);
    }

    private static String getMD5Hash(final String original) throws Throwable {
        final MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(original.getBytes());
        byte[] digest = md.digest();
        final StringBuffer sb = new StringBuffer();
        for (byte b : digest) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    private static String getGradebookLink(String html) throws IOException {
        String key = "<a class=\"list-group-item \" href=\"PXP2_Gradebook.aspx?";
        int startIndex = html.indexOf(key);
        if (startIndex == -1) {
            throw new IOException("Expected <" + key + "> to be present in HTML.");
        }
        String str = html.substring(startIndex + 34, html.length());
        startIndex = str.indexOf("\"");
        if (startIndex == -1) {
            throw new IOException("Expected single double quote be present in HTML.");
        }
        str = str.substring(0, startIndex);
        return str;
    }

    public Content execute() throws Throwable {
        // Create a trust manager that does not validate certificate chains
        final TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }

                    public void checkClientTrusted(
                            java.security.cert.X509Certificate[] certs, String authType) {
                    }

                    public void checkServerTrusted(
                            java.security.cert.X509Certificate[] certs, String authType) {
                    }
                }
        };

        final SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, trustAllCerts, new java.security.SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());


        final CookieManager cm = new CookieManager();
        cm.setCookiePolicy(CookiePolicy.ACCEPT_ALL);
        CookieHandler.setDefault(cm);

        // one instance, reuse
        final HttpClient httpClient = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_2)
                .cookieHandler(CookieHandler.getDefault())
                .connectTimeout(Duration.ofSeconds(30))
                .followRedirects(HttpClient.Redirect.ALWAYS)
                //.proxy(ProxySelector.of(new InetSocketAddress("localhost", 8888)))
                .sslContext(sc) // SSL context 'sc' initialised as earlier
                .build();


        final Map<String, String> map = doGetLoginPage(httpClient);

        if (map.size() != 3) {
            throw new IOException("Expected 4 items to be in the map!");
        }

        map.put(USERNAME, lcpsUserName);
        map.put(PASSWORD, lcpsPassword);

        String html = doPostLogin(httpClient, map);

        if (StringUtils.isEmpty(html))
        {
            throw new IOException("doPostLogin() HTML was empty!");
        }

        final String gradebookLink = getGradebookLink(html);
        if (StringUtils.isEmpty(gradebookLink))
        {
            throw new IOException("getGradebookLink() HTML was empty!");
        }

        html = doGetGradeBook(httpClient, gradebookLink);
        if (StringUtils.isEmpty(gradebookLink))
        {
            throw new IOException("doGetGradeBook() HTML was empty!");
        }

        final Document document = Jsoup.parseBodyFragment(html);
        if (document == null)
        {
            throw new IOException("document was null!");
        }

        final Element element = document.getElementById("gradebook-content");
        if (element == null)
        {
            throw new IOException("gradebook-content div tag not present in HTML!");
        }

        String gradebookContent = element.outerHtml();
        if (StringUtils.isEmpty(gradebookContent))
        {
            throw new IOException("Gradebook content was empty!");
        }
        gradebookContent = gradebookContent.trim();
        final String md5Hash = getMD5Hash(gradebookContent);

        final Content content = new Content();
        content.raw = gradebookContent;
        content.hash = md5Hash;
        return content;
    }

    public Map<String, String> doGetLoginPage(final HttpClient httpClient) throws IOException, InterruptedException {

        final Map map = new HashMap<String, String>();

        final HttpRequest request = HttpRequest.newBuilder()
                .GET()
                .setHeader("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:72.0) Gecko/20100101 Firefox/72.0")
                .uri(URI.create("https://portal.lcps.org/PXP2_Login_Student.aspx?regenerateSessionId=True"))
                .build();

        final HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        int statusCode = response.statusCode();

        if (response.statusCode() != 200) {
            throw new IOException("Expected a 200 response code.  received: <" + statusCode + ">");

        }

        final String html = response.body();


        final String viewState = getHiddenFieldValue(VIEWSTATE_KEY, html);
        final String viewStateGenerator = getHiddenFieldValue(VIEWSTATE_GENERATOR_KEY, html);
        final String eventValidation = getHiddenFieldValue(EVENTVALIDATION_KEY, html);


        map.put(VIEWSTATE_KEY, viewState);
        map.put(VIEWSTATE_GENERATOR_KEY, viewStateGenerator);
        map.put(EVENTVALIDATION_KEY, eventValidation);

        return map;
    }

    public String doGetGradeBook(final HttpClient httpClient, final String pageUrl) throws IOException, InterruptedException {
        final HttpRequest request = HttpRequest.newBuilder()
                .GET()
                .setHeader("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:72.0) Gecko/20100101 Firefox/72.0")
                .uri(URI.create("https://portal.lcps.org/" + pageUrl))
                .build();

        final HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        int statusCode = response.statusCode();

        if (response.statusCode() != 200) {
            throw new IOException("Expected a 200 response code.  received: <" + statusCode + ">");

        }

        final String html = response.body();
        return html;
    }

    public String doPostLogin(final HttpClient httpClient, final Map<String, String> map) throws IOException, InterruptedException {


        if (map == null) {
            throw new IOException("Expected map to be non null!");
        }

        if (map.size() != 5) {
            throw new IOException("Expected 6 items to be in the map!");
        }

        httpClient.followRedirects();

        final StringBuilder builder = new StringBuilder();
        builder.append(VIEWSTATE_KEY).append("=").append(encodeValue(map.get(VIEWSTATE_KEY)));
        builder.append("&");
        builder.append(VIEWSTATE_GENERATOR_KEY).append("=").append(encodeValue(map.get(VIEWSTATE_GENERATOR_KEY)));
        builder.append("&");
        builder.append(EVENTVALIDATION_KEY).append("=").append(encodeValue(map.get(EVENTVALIDATION_KEY)));
        builder.append("&");
        builder.append(USERNAME).append("=").append(map.get(USERNAME));
        builder.append("&");
        builder.append(PASSWORD).append("=").append(map.get(PASSWORD));

        final String body = builder.toString();

        final HttpRequest request = HttpRequest.newBuilder()
                .POST(BodyPublishers.ofString(body))
                .setHeader("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:72.0) Gecko/20100101 Firefox/72.0")
                .setHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
                .setHeader("Accept-Language", "en-US,en;q=0.5")
                .setHeader("Accept-Encoding", "gzip, deflate")
                .setHeader("Content-Type", "application/x-www-form-urlencoded")
                .setHeader("Origin", "https://portal.lcps.org")
                .setHeader("Referer", "https://portal.lcps.org/PXP2_Login_Student.aspx?regenerateSessionId=True")
                .uri(URI.create("https://portal.lcps.org/PXP2_Login_Student.aspx?regenerateSessionId=True"))
                .build();

        final HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        int statusCode = response.statusCode();

        if (response.statusCode() != 200) {
            throw new IOException("Expected a 200 response code.  received: <" + statusCode + ">");

        }

        final String html = response.body();

        if (html.indexOf(VALID_AUTHENTICATED_ASSERTION) == -1) {
            throw new IOException("Expected < " + VALID_AUTHENTICATED_ASSERTION + "> to be present in html.");
        }

        return html;
    }

    protected String encodeValue(String value) throws UnsupportedEncodingException {
        return URLEncoder.encode(value, StandardCharsets.UTF_8.toString());
    }


    // <input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="0AfpKSyQwDjnDsA/PH98oB0c1oHsVYpefZMgtuvozEUpYvD635IGf1KLjgvP8Ihy+fFXRUcMeGQ8pKfOqd7XCUbxcO0RwrSPpXhSDG2BZik=" />
    protected String getHiddenFieldValue(final String key, final String html) throws IOException {

        final String searchPattern = "<input type=\"hidden\" name=\"" + key + "\" id=\"" + key + "\" value=\"";

        int startIndex = html.indexOf(searchPattern);
        if (startIndex == -1) {
            throw new IOException("Could not find pattern: <" + searchPattern + "> in raw HTML.");
        }

        final String str = html.substring(startIndex + searchPattern.length(), html.length());

        startIndex = str.indexOf("\"");
        if (startIndex == -1) {
            throw new IOException("Expected to find a single double quote but did not in raw html.");

        }

        return str.substring(0, startIndex);
    }
}

class ScheduledTask extends TimerTask {

    private static Content lastContent;


    private final String smtpHost;
    private final int smtpPort;
    private final String smtpUserName;
    private final String smtpPassword;
    private final String smtpTo;
    private final String smtpFrom;


    private final String lcpsUserName;
    private final String lcpsPassword;

    public ScheduledTask(String smtpHost, int smtpPort, String smtpUserName, String smtpPassword, String smtpTo, String smtpFrom, String lcpsUserName, String lcpsPassword) {
        this.smtpHost = smtpHost;
        this.smtpPort = smtpPort;
        this.smtpUserName = smtpUserName;
        this.smtpPassword = smtpPassword;
        this.smtpTo = smtpTo;
        this.smtpFrom = smtpFrom;

        this.lcpsUserName = lcpsUserName;
        this.lcpsPassword = lcpsPassword;
    }

    private void sendEmail(final String diff) throws Throwable {
        final Properties prop = new Properties();
        prop.put("mail.smtp.auth", true);
        prop.put("mail.smtp.starttls.enable", "true");
        prop.put("mail.smtp.host", smtpHost);
        prop.put("mail.smtp.port", smtpPort);
        prop.put("mail.smtp.ssl.trust", smtpHost);

        final Session session = Session.getInstance(prop, new javax.mail.Authenticator() {
            @Override
            protected javax.mail.PasswordAuthentication getPasswordAuthentication() {
                return new javax.mail.PasswordAuthentication(smtpUserName, smtpPassword);
            }
        });

        Message message = new MimeMessage(session);
        message.setFrom(new InternetAddress(smtpFrom));
        message.setRecipients(
                Message.RecipientType.TO, InternetAddress.parse(smtpTo));
        message.setSubject("StudentVue Java Bot!");

        String msg = "Check your Grades in StudentVue, they *may* have changed!!! " + new Date() + ". Diff below\n" + diff;

        MimeBodyPart mimeBodyPart = new MimeBodyPart();
        mimeBodyPart.setContent(msg, "text/plain");

        Multipart multipart = new MimeMultipart();
        multipart.addBodyPart(mimeBodyPart);

        message.setContent(multipart);

        Transport.send(message);
    }

    public void run() {
        final Main main = new Main(lcpsUserName, lcpsPassword);


        try {
            final Content content = main.execute();
            if (lastContent == null) {
                lastContent = content;
            }

            if (content.hash.equals(lastContent.hash)) {
            } else {
                System.out.println("Hash Changed: " + new Date());
                final String diff = StringUtils.difference(content.raw, lastContent.raw);
                lastContent = content;
                sendEmail(diff);
            }

        } catch (Throwable t) {
            System.out.println("Failed on: " + new Date());
            t.printStackTrace();
        }

    }
}

class Content
{
    protected String hash;
    protected String raw;
}