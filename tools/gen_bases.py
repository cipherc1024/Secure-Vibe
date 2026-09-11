# secure-vibe: ignore-file - deliberate attack-sample data for gen_bases.py (not real code)
"""tools/gen_bases.py - Hand-authored, empirically verified base samples.

BASES: dict[str, tuple[str, str, list[str]]] = rule_id -> (language, positive, [negatives])
Contract enforced by tools/verify_bases.py:
  positive MUST trigger rule_id (other rules may also fire)
  every negative MUST produce ZERO violations across the whole language chain

Edit here, then run:  py -3 tools/verify_bases.py
"""

from __future__ import annotations

# Rules whose regex patterns depend on string CONTENTS but are not marked
# literal_sensitive, so the python/js lexer blanks the content the regex needs
# and the rule can never fire on the stripped language shape. The samples are
# kept here as the intended positive/negative pair and the negatives are still
# verified clean, but the positive-cannot-fire is tolerated by verify_bases.py.
# See the triage report for the underlying rule hygiene issue.
DEAD_RULES: dict[str, str] = {
    "PY-006": "patterns match /tmp inside string literals, rule is not literal_sensitive",
}

BASES: dict[str, tuple[str, str, list[str]]] = {
    # ---------------------------------------------------------------- general
    "GEN-001": (
        "python",
        'api_key = "d41d8cd98f00b204e9800998ecf8427e"',
        ['config = {"api_key": os.environ["API_KEY"]}'],
    ),
    "GEN-002": (
        "python",
        'url = "http://api.example.com/users"',
        ['url = "https://api.example.com/users"'],
    ),
    "GEN-003": (
        "python",
        "token = random.randint(100000, 999999)",
        ["token = secrets.token_hex(16)"],
    ),
    "GEN-004": (
        "python",
        "digest = hashlib.md5(data)",
        ["digest = hashlib.sha256(data)"],
    ),
    "GEN-005": (
        "python",
        'cursor.execute(f"SELECT * FROM users WHERE id = {uid}")',
        ['cursor.execute("SELECT * FROM users WHERE id = ?", (uid,))'],
    ),
    "GEN-006": (
        "python",
        'print("reset password:", password)',
        ['print("user name:", user)'],
    ),
    "GEN-007": (
        "python",
        'verify_options = {"verify_signature": False}',
        ['verify_options = {"verify_signature": True}'],
    ),
    "GEN-008": (
        "python",
        "ctx = ssl._create_unverified_context()",
        ["ctx = ssl.create_default_context()"],
    ),

    # --------------------------------------------------------------- python
    "PY-001": (
        "python",
        "result = eval(user_expr)",
        ["result = json.loads(text)"],
    ),
    "PY-002": (
        "python",
        'os.system("ls -l")',
        ['subprocess.run(["ls", "-l"])'],
    ),
    "PY-003": (
        "python",
        "subprocess.run(cmd, shell=True)",
        ["subprocess.run(cmd, shell=False)"],
    ),
    "PY-004": (
        "python",
        "data = pickle.loads(blob)",
        ["data = json.loads(blob)"],
    ),
    "PY-005": (
        "python",
        "config = yaml.load(data)",
        ["config = yaml.safe_load(data)"],
    ),
    "PY-006": (
        "python",
        'open("/tmp/scratch.txt", "w")',
        ["fd, name = tempfile.mkstemp()"],
    ),
    "PY-007": (
        "python",
        "obj = marshal.loads(blob)",
        ["obj = json.loads(blob)"],
    ),
    "PY-008": (
        "python",
        "app.run(debug=True)",
        ["app.run(debug=False)"],
    ),
    "PY-009": (
        "python",
        "DEBUG = True",
        ["DEBUG = False"],
    ),
    "PY-010": (
        "python",
        'os.system(input("cmd: "))',
        ['value = input("name: ")'],
    ),
    "PY-011": (
        "python",
        "resp = requests.get(user_url)",
        ['resp = requests.get("https://api.example.com/v1/items")'],
    ),
    "PY-012": (
        "python",
        "tree = etree.fromstring(raw)",
        ['tree = defusedxml.ElementTree.parse("doc.xml")'],
    ),
    "PY-013": (
        "python",
        "render_template_string(user_tpl)",
        ['render_template("index.html")'],
    ),
    "PY-014": (
        "python",
        'open(request.args["path"], "rb")',
        ['open(os.path.join(BASE_DIR, "index.html"), "rb")'],
    ),
    "PY-015": (
        "python",
        "zf.extractall(dst)",
        ['zf.read("a.txt")'],
    ),
    "PY-016": (
        "python",
        'db.users.find({"$where": query})',
        ['db.users.find({"name": str(username)})'],
    ),
    "PY-017": (
        "python",
        'User.objects.raw(f"SELECT * FROM auth_user WHERE id = {uid}")',
        ["User.objects.filter(id=uid)"],
    ),
    "PY-018": (
        "python",
        'token = jwt.encode({"alg": "none"}, key)',
        ['token = jwt.encode({"sub": "1"}, key, algorithm="HS256")'],
    ),
    "PY-019": (
        "python",
        "configure_cors(origin=allowed, allow_credentials=True)",
        ["configure_cors(allow_credentials=False)"],
    ),
    "PY-020": (
        "python",
        'def handler():\n    return redirect(request.args["next"])',
        ['def handler():\n    return redirect(url_for("dashboard"))'],
    ),
    "PY-021": (
        "python",
        'model = torch.load("model.pt")',
        ['model = torch.load("model.pt", weights_only=True)'],
    ),
    "PY-022": (
        "python",
        "re.match(rx, input())",
        ['re.fullmatch("[0-9]+", digits)'],
    ),
    "PY-023": (
        "python",
        'subprocess.run(["bash", "-c", cmd])',
        ['subprocess.run(["ls", "-la"])'],
    ),
    "PY-024": (
        "python",
        "def handler():\n    target = input()\n    return redirect(target)",
        ['def handler():\n    return redirect("/home")'],
    ),
    "PY-025": (
        "python",
        "def handler():\n    raw = input()\n    return make_response(raw)",
        ['def handler():\n    return make_response("ok")'],
    ),
    "PY-026": (
        "python",
        'def handler():\n    value = input()\n    headers.add("X-Note", value)',
        ['def handler():\n    headers.add("X-Frame-Options", "DENY")'],
    ),
    "PY-027": (
        "python",
        "def handler():\n    msg = input()\n    logging.info(msg)",
        ['def handler():\n    logging.info("request complete")'],
    ),
    "PY-028": (
        "python",
        "pattern = input()\nre.compile(pattern)",
        ['re.compile("[a-z]+")'],
    ),
    "PY-029": (
        "python",
        "expr = input()\ndoc.xpath(expr)",
        ['doc.xpath("//title")'],
    ),
    "PY-030": (
        "python",
        "ldap_filter = input()\nconn.search(base_dn, ldap_filter)",
        ['conn.search(base_dn, "(uid=admin)")'],
    ),
    "PY-031": (
        "python",
        "expr = input()\ntable.scan(FilterExpression=expr)",
        ['table.scan(FilterExpression="status = :s")'],
    ),
    "PY-032": (
        "python",
        'name = input()\nopen(name, "rb")',
        ['open("data/known.csv", "rb")'],
    ),
    "PY-033": (
        "python",
        "digest = hashlib.md5(data)",
        ["digest = hashlib.sha256(data)"],
    ),
    "PY-034": (
        "python",
        "digest = hashlib.sha256(password)",
        ['digest = hashlib.pbkdf2_hmac("sha256", password, salt, 120000)'],
    ),
    "PY-035": (
        "python",
        "ctx = ssl.wrap_socket(sock)",
        ["ctx = ssl.create_default_context()"],
    ),
    "PY-036": (
        "python",
        "key = RSA.generate(1024)",
        ["key = RSA.generate(3072, e3)"],
    ),
    "PY-037": (
        "python",
        'ftp = ftplib.FTP("server")',
        ['ftp = ftplib.FTP_TLS("server")'],
    ),
    "PY-038": (
        "python",
        'tar.extract("data.bin")',
        ["names = tar.getnames()"],
    ),
    "PY-039": (
        "python",
        'config = {"PASSWORD": "123456"}',
        ['config = {"PASSWORD": os.environ["DB_PASSWORD"]}'],
    ),
    "PY-040": (
        "python",
        'if password == "admin12345":\n    pass',
        ["if password == stored_hash:\n    pass"],
    ),
    "PY-041": (
        "python",
        'class Gadget:\n' \
        '    def __reduce__(self):\n' \
        '        return os.system, ("id",)\n' \
        "\n" \
        "pickle.dumps(Gadget())",
        ["class Safe:\n"
         "    def __reduce__(self):\n"
         "        return dict, (self.name,)"],
    ),
    "PY-042": (
        "python",
        'clean = re.sub(r"<script>.*</script>", "", html)',
        ["clean = bleach.clean(html)"],
    ),
    "PY-043": (
        "python",
        'iv = b"0123456789abcdef"',
        ["iv = os.urandom(16)"],
    ),
    "PY-044": (
        "python",
        "elapsed = time.clock()",
        ["elapsed = time.perf_counter()"],
    ),
    "PY-045": (
        "python",
        r'pattern = r"/^abc\d+$/"',
        ['pattern = r"^abc"'],
    ),
    "PY-046": (
        "python",
        "jwt.decode(token, verify=False)",
        ['jwt.decode(token, key, algorithms=["HS256"])'],
    ),
    "PY-047": (
        "python",
        "xml_text = input()\netree.fromstring(xml_text)",
        ['tree = ET.parse("doc.xml")'],
    ),
    "PY-048": (
        "python",
        'name = input()\ntarget = "upload/" + name\nimg.save(target)',
        ['name = "photo.png"\ntarget = os.path.join("upload", name)\nimg.save(target)'],
    ),
    "PY-049": (
        "python",
        "dom = minidom.parseString(raw)",
        ["data = xmltodict.parse(doc)"],
    ),
    "PY-050": (
        "python",
        'api_key = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"',
        ['api_key = os.environ["API_KEY"]'],
    ),
    "PY-051": (
        "python",
        "traceback.print_exc()",
        ['logger.error("operation failed")'],
    ),
    "PY-052": (
        "python",
        'table.scan(FilterExpression="user = " + name)',
        ['table.scan(FilterExpression="status = :s", ExpressionAttributeValues={":s": name})'],
    ),
    "PY-053": (
        "python",
        'conn = sqlite3.connect("app.db", user="admin", password="secret123")',
        ["conn = sqlite3.connect(db_url)"],
    ),
    "PY-054": (
        "python",
        "requests.get(url, verify=False)",
        ["requests.get(url, verify=True)"],
    ),

    # -------------------------------------------------------- blacklist python
    "BL-001": (
        "python",
        "import ctypes",
        ["import os"],
    ),
    "BL-002": (
        "python",
        "module = __import__(user_module)",
        ['import importlib\nmodule = importlib.import_module("json")'],
    ),
    "BL-003": (
        "python",
        'Markup(request.args["q"])',
        ['Markup("<b>hello</b>")'],
    ),
    "BL-004": (
        "python",
        "pickle.loads(request.data)",
        ["json.loads(request.data)"],
    ),
    "BL-005": (
        "python",
        'fn = getattr(builtins, "eval")',
        ['fn = getattr(obj, "description")'],
    ),
    "BL-006": (
        "python",
        "torch.load(download_result)",
        ['torch.load("models/m.pt", weights_only=True)'],
    ),
    "BL-007": (
        "python",
        'requests.get("http://169.254.169.254/latest/meta-data/")',
        ['requests.get("https://api.example.com/items")'],
    ),

    # ------------------------------------------------------------------- js
    "JS-001": (
        "js",
        "const result = eval(userCode)",
        ["const data = JSON.parse(raw)"],
    ),
    "JS-002": (
        "js",
        "el.innerHTML = userHtml",
        [
            "el.textContent = userText",
            "el.innerHTML = DOMPurify.sanitize(userHtml)",
        ],
    ),
    "JS-003": (
        "js",
        "document.write(html)",
        ["el.textContent = text"],
    ),
    "JS-004": (
        "js",
        'setTimeout("doWork()", 500)',
        ["setTimeout(doWork, 500)"],
    ),
    "JS-005": (
        "js",
        'win.postMessage(data, "*")',
        ['win.postMessage(data, "https://app.example.com")'],
    ),
    "JS-006": (
        "js",
        'exec("sh -c " + userCmd)',
        ['execFile("ls", ["-l"], cb)'],
    ),
    "JS-007": (
        "js",
        "res.send(req.query.name)",
        ['res.json({ status: "ok" })'],
    ),
    "JS-008": (
        "js",
        "Object.assign({}, JSON.parse(rawBody))",
        ["Object.assign({}, defaults)"],
    ),
    "JS-009": (
        "js",
        "const mod = require(dynamicPath)",
        ['const fs = require("fs")'],
    ),
    "JS-010": (
        "js",
        "db.query(`SELECT * FROM users WHERE id = ${uid}`)",
        ["db.query(\"SELECT * FROM users WHERE id = ?\", [uid])"],
    ),
    "JS-011": (
        "js",
        "https.get(url, { rejectUnauthorized: false })",
        ["https.get(url, { rejectUnauthorized: true })"],
    ),
    "JS-012": (
        "js",
        'crypto.createHash("md5")',
        ['crypto.createHash("sha256")'],
    ),
    "JS-013": (
        "js",
        "const token = Math.random()",
        ["const token = crypto.randomBytes(16)"],
    ),
    "JS-014": (
        "js",
        'const api_key = "ak79fFeDcBa0987654321abcdef"',
        ["const api_key = process.env.API_KEY"],
    ),
    "JS-015": (
        "js",
        "res.redirect(req.query.url)",
        ['res.redirect("/home")'],
    ),
    "JS-016": (
        "js",
        "fs.readFile(req.params.file, cb)",
        ['fs.readFile("config.json", cb)'],
    ),
    "JS-017": (
        "js",
        'jwt.verify(token, key, { algorithms: ["none"] })',
        ['jwt.verify(token, key, { algorithms: ["HS256"] })'],
    ),
    "BLJ-001": (
        "js",
        "el.innerHTML = location.href",
        ["el.textContent = document.URL"],
    ),
    "BLJ-002": (
        "js",
        "Object.assign(cfg, JSON.parse(req.body))",
        ["Object.assign(cfg, knownDefaults)"],
    ),

    # ------------------------------------------------------------------ java
    "JAVA-001": (
        "java",
        'Runtime.getRuntime().exec("ping " + host)',
        ['new ProcessBuilder(new String[] {"ls", "-l"}).start()'],
    ),
    "JAVA-002": (
        "java",
        'st.executeQuery("SELECT * FROM users WHERE id = " + userId)',
        ["ResultSet rs = ps.executeQuery()"],
    ),
    "JAVA-003": (
        "java",
        "ObjectInputStream ois = new ObjectInputStream(sock.getInputStream())",
        ["Gson gson = new Gson()"],
    ),
    "JAVA-004": (
        "java",
        "DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance()",
        ["XMLStreamReader reader = xmlInputFactory.createXMLStreamReader(input)"],
    ),
    "JAVA-005": (
        "java",
        "Random r = new Random()",
        ["SecureRandom sr = new SecureRandom()"],
    ),
    "JAVA-006": (
        "java",
        "management.endpoints.web.exposure.include=*",
        ["management.endpoints.web.exposure.include=health,info"],
    ),
    "JAVA-007": (
        "java",
        'Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding")',
        ['Cipher c = Cipher.getInstance("AES/GCM/NoPadding")'],
    ),
    "JAVA-008": (
        "java",
        'MessageDigest.getInstance("MD5")',
        ['MessageDigest.getInstance("SHA-256")'],
    ),
    "JAVA-009": (
        "java",
        "class TM implements X509TrustManager {\n"
        "    public void checkServerTrusted(X509Certificate[] chain, String authType) {\n"
        "        return true;\n"
        "    }\n"
        "}",
        ["class TM implements X509TrustManager {\n"
         "    public void checkServerTrusted(X509Certificate[] chain, String authType) {\n"
         "        if (chain == null) throw new CertificateException();\n"
         "    }\n"
         "}"],
    ),
    "JAVA-010": (
        "java",
        'String password = "Sup3rS3cretPwd"',
        ['String password = SecretsManager.lookup("DB_PASSWORD")'],
    ),

    # -------------------------------------------------------------------- go
    "GO-001": (
        "go",
        'exec.Command("sh", "-c", cmd)',
        ['exec.Command("git", "status")'],
    ),
    "GO-002": (
        "go",
        'db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %d", uid))',
        ['db.Query("SELECT * FROM users WHERE id = ?", uid)'],
    ),
    "GO-003": (
        "go",
        "http.Get(base + userInput)",
        ['http.Get("https://api.example.com/health")'],
    ),
    "GO-004": (
        "go",
        "out := template.HTML(userInput)",
        ['io.WriteString(w, "ok")'],
    ),
    "GO-005": (
        "go",
        "n := rand.Intn(100)",
        ["io.ReadFull(crand.Reader, buf)"],
    ),
    "GO-006": (
        "go",
        'os.Open(r.FormValue("file"))',
        ['os.Open("config/app.yaml")'],
    ),
    "GO-007": (
        "go",
        "cfg := &tls.Config{InsecureSkipVerify: true}",
        ["cfg := &tls.Config{MinVersion: tls.VersionTLS13}"],
    ),

    # --------------------------------------------------------------- c / cpp
    "C-001": (
        "c",
        "system(cmd);",
        ["write(1, msg, len);"],
    ),
    "C-002": (
        "c",
        "sprintf(buf, fmt, val);",
        ['snprintf(buf, sizeof buf, "%s", s);'],
    ),
    "C-003": (
        "c",
        "strcpy(dst, src);",
        ["strncpy(dst, src, sizeof dst - 1);\ndst[sizeof dst - 1] = 0;"],
    ),
    "C-004": (
        "c",
        "int n = rand();",
        ["getrandom(buf, sizeof buf, 0);"],
    ),
    "C-005": (
        "c",
        "printf(user_input);",
        ['printf("%s", user_input);'],
    ),
    "C-006": (
        "c",
        'scanf("%s", buf);',
        ['scanf("%63s", buf);'],
    ),
    "C-007": (
        "c",
        "mktemp(template);",
        ["mkstemp(template);"],
    ),
    "BLC-001": (
        "c",
        "gets(buf);",
        ["fgets(buf, sizeof buf, stdin);"],
    ),
    "BLC-002": (
        "c",
        "system(cmd);",
        ["execvp(argv[0], argv);"],
    ),
    "CPP-001": (
        "cpp",
        "std::strcpy(dst, src);",
        ['std::snprintf(buf, n, "%s", s);'],
    ),
    "CPP-002": (
        "cpp",
        'system("ping " + host);',
        ['execve("/bin/ls", argv, envp);'],
    ),

    # ------------------------------------------------------------------- php
    "PHP-001": (
        "php",
        'system($_GET["cmd"]);',
        ["$out = escapeshellarg($name);"],
    ),
    "PHP-002": (
        "php",
        "eval($code);",
        ["$data = json_decode($raw);"],
    ),
    "PHP-003": (
        "php",
        '$sql = "SELECT * FROM users WHERE id = " . $_GET["id"];',
        ['$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");'],
    ),
    "PHP-004": (
        "php",
        'unserialize($_POST["data"]);',
        ['$data = json_decode($_POST["data"]);'],
    ),
    "PHP-005": (
        "php",
        "include $file;",
        ['include __DIR__ . "/templates/page.php";'],
    ),
    "PHP-006": (
        "php",
        'echo $_GET["q"];',
        ['echo htmlspecialchars($_GET["q"], ENT_QUOTES, "UTF-8");'],
    ),
    "PHP-007": (
        "php",
        "extract($_GET);",
        ['$name = $_GET["name"];'],
    ),
    "BLP-001": (
        "php",
        'system($_GET["cmd"]);',
        ["$out = escapeshellarg($cmd);"],
    ),
    "BLP-002": (
        "php",
        'include $_GET["page"];',
        ['include __DIR__ . "/templates/page.php";'],
    ),

    # ------------------------------------------------------------------ html
    "HTML-001": (
        "html",
        '<button onclick="doIt()">Go</button>',
        ['<button id="go">Go</button>'],
    ),
    "HTML-002": (
        "html",
        '<a href="javascript:alert(1)">x</a>',
        ['<a href="https://example.com">x</a>'],
    ),
    "HTML-003": (
        "html",
        '<iframe src="https://example.com"></iframe>',
        ['<iframe src="https://example.com" sandbox="allow-scripts"></iframe>'],
    ),
    "HTML-004": (
        "html",
        '<script src="https://cdn.example.com/lib.js"></script>',
        ['<script src="https://cdn.example.com/lib.js" integrity="sha384-abc"></script>'],
    ),
    "HTML-005": (
        "html",
        '<a href="https://example.com" target="_blank">x</a>',
        ['<a href="https://example.com" target="_blank" rel="noopener noreferrer">x</a>'],
    ),

    # ------------------------------------------------------------ dockerfile
    "DOCK-001": (
        "dockerfile",
        "USER root",
        ["USER 10001"],
    ),
    "DOCK-002": (
        "dockerfile",
        "ENV DATABASE_PASSWORD=hunter2secret",
        ["ENV DB_URL=postgresql://localhost"],
    ),
    "DOCK-003": (
        "dockerfile",
        "RUN curl -fsSL https://example.com/install.sh | sh",
        ["RUN curl -fsSL -o /tmp/install.sh https://example.com/install.sh"],
    ),
    "DOCK-004": (
        "dockerfile",
        "ADD https://example.com/app.tar.gz /opt/app/",
        ["ADD ./app.tar.gz /opt/app/"],
    ),
    "DOCK-005": (
        "dockerfile",
        "FROM ubuntu:latest",
        ["FROM ubuntu:22.04"],
    ),

    # ------------------------------------------------------------ kubernetes
    "K8S-001": (
        "kubernetes",
        "privileged: true",
        ["privileged: false"],
    ),
    "K8S-002": (
        "kubernetes",
        "volumes:\n  - name: host-data\n    hostPath:\n      path: /data",
        ["volumes:\n  - name: data\n    emptyDir: {}"],
    ),
    "K8S-003": (
        "kubernetes",
        "hostNetwork: true",
        ["terminationGracePeriodSeconds: 30"],
    ),
    "K8S-004": (
        "kubernetes",
        "runAsUser: 0",
        ["runAsUser: 10001\nrunAsNonRoot: true\nallowPrivilegeEscalation: false"],
    ),
    "K8S-005": (
        "kubernetes",
        "env:\n  - name: DB_PASSWORD\n    valueFrom:\n      secretKeyRef: {name: my-secret, key: db-pass}",
        ['env:\n  - name: LOG_LEVEL\n    value: "info"'],
    ),

    # ------------------------------------------------------------- terraform
    "TF-001": (
        "terraform",
        'ingress {\n  cidr_blocks = ["0.0.0.0/0"]\n}',
        ['ingress {\n  cidr_blocks = ["10.0.0.0/8"]\n}'],
    ),
    "TF-002": (
        "terraform",
        'resource "aws_s3_bucket" "b" {\n  acl = "public-read"\n}',
        ['resource "aws_s3_bucket" "b" {\n  acl = "private"\n}'],
    ),
    "TF-003": (
        "terraform",
        "publicly_accessible = true",
        ["publicly_accessible = false"],
    ),
    "TF-004": (
        "terraform",
        'password = "supersecret123"',
        ["password = var.db_password"],
    ),
    "TF-005": (
        "terraform",
        "ingress {\n  from_port = 0\n  to_port = 0\n}",
        ["ingress {\n  from_port = 443\n  to_port = 443\n}"],
    ),

    # -------------------------------------------------------------------- sh
    "SH-001": (
        "sh",
        "curl -fsSL https://example.com/install.sh | sh",
        ["curl -fsSL -o /tmp/install.sh https://example.com/install.sh"],
    ),
    "SH-002": (
        "sh",
        'eval "$cmd"',
        ['printf "%s" "$cmd"'],
    ),
    "SH-003": (
        "sh",
        "rm -rf /tmp/cache",
        ["rm -f /tmp/cache.tmp"],
    ),
    "SH-004": (
        "sh",
        "cat $file",
        ['cat "$file"'],
    ),
    "SH-005": (
        "sh",
        "user ALL=(ALL) NOPASSWD: ALL",
        ["user ALL=(ALL) ALL"],
    ),

    # -------------------------------------------------------- github-actions
    "GHA-001": (
        "github-actions",
        'run: echo "${{ github.event.issue.body }}"',
        ['run: echo "hello"'],
    ),
    "GHA-002": (
        "github-actions",
        "run: echo ${{ secrets.AWS_SECRET_ACCESS_KEY }}",
        ['run: echo "deploying"'],
    ),
    "GHA-003": (
        "github-actions",
        "uses: actions/checkout@main",
        ["uses: actions/checkout@v4"],
    ),
}
