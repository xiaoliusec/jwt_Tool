package burp;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;

public class JWTTool implements IBurpExtender, ITab, IContextMenuFactory
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JPanel mainPanel;
    private PrintWriter stdout;
    
    private JList<String> requestList;
    private DefaultListModel<String> listModel;
    private List<IHttpRequestResponse> httpMessages = new ArrayList<>();
    
    private JTextArea jwtInputArea;
    private JTextArea headerArea;
    private JTextArea payloadArea;
    private JTextField verifyField;
    private JTextField secretField;
    
    private String originalHeaderBase64;
    private String originalPayloadBase64;
    
    private JComboBox<String> algorithmCombo;
    private JComboBox<String> encodingCombo;
    private JButton encodeBtn;
    private JButton decodeBtn;
    private JButton verifyBtn;
    private JButton selectDictBtn;
    private JButton builtInDictBtn;
    private JTextField dictPathField;
    private JButton startBtn;
    private JButton stopBtn;
    private JProgressBar progressBar;
    private JTextArea resultArea;
    
    private ExecutorService executor;
    private AtomicBoolean isRunning = new AtomicBoolean(false);
    private String currentAlgorithm = "HS256";
    private List<String> wordlist = new ArrayList<>();
    private String selectedWordlistPath = "";
    
    private String[] builtInWords = {
        "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234", "111111", 
        "1234567", "dragon", "123123", "baseball", "abc123", "football", "monkey", "letmein",
        "shadow", "master", "666666", "qwertyuiop", "123321", "mustang", "1234567890",
        "michael", "654321", "superman", "1qaz2wsx", "121212", "qazwsx", "jordan", "jennifer",
        "admin", "secret", "root", "toor", "test", "guest"
    };

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stdout.println("JWT Tool v1.0 loaded!");
        
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        callbacks.setExtensionName("JWT Tool v1.0");
        
        executor = Executors.newSingleThreadExecutor();
        
        SwingUtilities.invokeLater(() -> {
            createUI();
            loadBuiltInDict(callbacks);
            dictPathField.addActionListener(e -> {
                String path = dictPathField.getText().trim();
                if (!path.isEmpty() && !path.equals("(无内置字典文件)")) {
                    loadDictionaryFromPath(path);
                }
            });
            callbacks.addSuiteTab(JWTTool.this);
            callbacks.registerContextMenuFactory(JWTTool.this);
        });
    }
    
    private void createUI()
    {
        mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
        
        // 第1列：数据包列表 20%
        JPanel leftPanel = createLeftPanel();
        
        // 第2列：JWT输入 30%
        JPanel jwtInputCol = createJwtInputColumn();
        
        // 第3列：操作按钮 10%
        JPanel actionCol = createActionColumn();
        
        // 第4列：JWT解析 40%
        JPanel rightPanel = createRightPanel();
        
        // 组合：第1列(20%) | 第2列(30%)
        JSplitPane split1 = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        split1.setResizeWeight(0.2);
        split1.setLeftComponent(leftPanel);
        split1.setRightComponent(jwtInputCol);
        
        // 组合：前两项(20%+30%=50%) | 第3列(10%)
        JSplitPane split2 = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        split2.setResizeWeight(0.5 / 0.6);  // 50% / (50%+10%) = 0.83
        split2.setLeftComponent(split1);
        split2.setRightComponent(actionCol);
        
        // 组合：前三列(20%+30%+10%=60%) | 第4列(40%)
        JSplitPane split3 = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        split3.setResizeWeight(0.6);  // 60% / 40%
        split3.setLeftComponent(split2);
        split3.setRightComponent(rightPanel);
        
        mainPanel.add(split3, BorderLayout.CENTER);
        mainPanel.add(createBottomPanel(), BorderLayout.SOUTH);
    }
    
    // 创建JWT输入列（第2列）
    private JPanel createJwtInputColumn()
    {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        
        JSplitPane vSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        vSplit.setResizeWeight(0.3);
        
        // 上半：JWT输入
        JPanel jwtInputPanel = new JPanel(new BorderLayout());
        jwtInputPanel.setBorder(BorderFactory.createTitledBorder("JWT输入"));
        jwtInputArea = new JTextArea(12, 1);
        jwtInputArea.setFont(new Font("Monospaced", Font.PLAIN, 13));
        jwtInputArea.setLineWrap(true);
        jwtInputArea.setWrapStyleWord(true);
        jwtInputPanel.add(new JScrollPane(jwtInputArea), BorderLayout.CENTER);
        
        // 下半：预留
        JPanel reservedPanel = new JPanel(new BorderLayout());
        reservedPanel.setBorder(BorderFactory.createTitledBorder("预留"));
        JLabel reservedLabel = new JLabel("此处另有用处", SwingConstants.CENTER);
        reservedLabel.setForeground(Color.GRAY);
        reservedLabel.setFont(new Font("微软雅黑", Font.PLAIN, 14));
        reservedPanel.add(reservedLabel, BorderLayout.CENTER);
        
        vSplit.setTopComponent(jwtInputPanel);
        vSplit.setBottomComponent(reservedPanel);
        
        panel.add(vSplit, BorderLayout.CENTER);
        return panel;
    }
    
    // 创建操作按钮列（第3列）
    private JPanel createActionColumn()
    {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder("操作"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(8, 5, 8, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        
        // 签名算法
        JLabel algLabel = new JLabel("签名算法:");
        algLabel.setFont(new Font("微软雅黑", Font.BOLD, 12));
        gbc.gridx = 0; gbc.gridy = 0;
        panel.add(algLabel, gbc);
        
        algorithmCombo = new JComboBox<>(new String[]{
            "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", 
            "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EdDSA", "None"
        });
        algorithmCombo.setFont(new Font("微软雅黑", Font.PLAIN, 11));
        gbc.gridx = 0; gbc.gridy = 1;
        panel.add(algorithmCombo, gbc);
        
        // 解码按钮
        decodeBtn = new JButton("解码 》");
        decodeBtn.setFont(new Font("微软雅黑", Font.BOLD, 13));
        decodeBtn.setPreferredSize(new Dimension(90, 35));
        decodeBtn.addActionListener(e -> decodeJwt());
        gbc.gridx = 0; gbc.gridy = 2;
        gbc.insets = new Insets(20, 5, 8, 5);
        panel.add(decodeBtn, gbc);
        
        // 编码按钮
        encodeBtn = new JButton("编码 《");
        encodeBtn.setFont(new Font("微软雅黑", Font.BOLD, 13));
        encodeBtn.setPreferredSize(new Dimension(90, 35));
        encodeBtn.addActionListener(e -> encodeJwt());
        gbc.gridx = 0; gbc.gridy = 3;
        gbc.insets = new Insets(8, 5, 8, 5);
        panel.add(encodeBtn, gbc);
        
        // 校验按钮
        verifyBtn = new JButton("校验");
        verifyBtn.setFont(new Font("微软雅黑", Font.BOLD, 13));
        verifyBtn.setPreferredSize(new Dimension(90, 35));
        verifyBtn.setBackground(new Color(33, 150, 243));
        verifyBtn.setForeground(Color.WHITE);
        verifyBtn.addActionListener(e -> verifySignature());
        gbc.gridx = 0; gbc.gridy = 4;
        panel.add(verifyBtn, gbc);
        
        return panel;
    }
    
    private JPanel createLeftPanel()
    {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createTitledBorder("数据包列表"));
        
        listModel = new DefaultListModel<>();
        requestList = new JList<>(listModel);
        requestList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        requestList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int index = requestList.getSelectedIndex();
                if (index >= 0 && index < httpMessages.size()) {
                    parseJwtFromRequest(httpMessages.get(index));
                }
            }
        });
        
        JScrollPane scrollPane = new JScrollPane(requestList);
        panel.add(scrollPane, BorderLayout.CENTER);
        
        JButton clearBtn = new JButton("清空");
        clearBtn.addActionListener(e -> {
            listModel.clear();
            httpMessages.clear();
            clearFields();
        });
        panel.add(clearBtn, BorderLayout.SOUTH);
        
        return panel;
    }
    
    private JPanel createActionPanel()
    {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder("操作"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(8, 5, 8, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        
        // 签名算法
        JLabel algLabel = new JLabel("签名算法:");
        algLabel.setFont(new Font("微软雅黑", Font.BOLD, 12));
        gbc.gridx = 0; gbc.gridy = 0;
        gbc.gridwidth = 1;
        panel.add(algLabel, gbc);
        
        algorithmCombo = new JComboBox<>(new String[]{
            "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", 
            "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EdDSA", "None"
        });
        algorithmCombo.setFont(new Font("微软雅黑", Font.PLAIN, 11));
        algorithmCombo.setPreferredSize(new Dimension(100, 28));
        gbc.gridx = 0; gbc.gridy = 1;
        panel.add(algorithmCombo, gbc);
        
        // 解码按钮
        decodeBtn = new JButton("解码 》");
        decodeBtn.setFont(new Font("微软雅黑", Font.BOLD, 13));
        decodeBtn.setPreferredSize(new Dimension(100, 35));
        decodeBtn.setMargin(new Insets(5, 5, 5, 5));
        decodeBtn.addActionListener(e -> decodeJwt());
        gbc.gridx = 0; gbc.gridy = 2;
        gbc.insets = new Insets(20, 5, 8, 5);
        panel.add(decodeBtn, gbc);
        
        // 编码按钮
        encodeBtn = new JButton("编码 《");
        encodeBtn.setFont(new Font("微软雅黑", Font.BOLD, 13));
        encodeBtn.setPreferredSize(new Dimension(100, 35));
        encodeBtn.setMargin(new Insets(5, 5, 5, 5));
        encodeBtn.addActionListener(e -> encodeJwt());
        gbc.gridx = 0; gbc.gridy = 3;
        gbc.insets = new Insets(8, 5, 8, 5);
        panel.add(encodeBtn, gbc);
        
        // 校验按钮
        verifyBtn = new JButton("校验");
        verifyBtn.setFont(new Font("微软雅黑", Font.BOLD, 13));
        verifyBtn.setPreferredSize(new Dimension(100, 35));
        verifyBtn.setMargin(new Insets(5, 5, 5, 5));
        verifyBtn.setBackground(new Color(33, 150, 243));
        verifyBtn.setForeground(Color.WHITE);
        verifyBtn.addActionListener(e -> verifySignature());
        gbc.gridx = 0; gbc.gridy = 4;
        panel.add(verifyBtn, gbc);
        
        return panel;
    }
    
    private JPanel createRightPanel()
    {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder("JWT解析"));
        panel.setPreferredSize(new Dimension(400, 0));
        panel.setMinimumSize(new Dimension(350, 0));
        
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(8, 8, 8, 8);
        gbc.fill = GridBagConstraints.BOTH;
        gbc.weightx = 1.0;
        
        // Header - 标签和输入框在同一行
        JPanel headerPanel = new JPanel(new BorderLayout(5, 0));
        JLabel headerLabel = new JLabel("Header:");
        headerLabel.setFont(new Font("微软雅黑", Font.BOLD, 14));
        headerLabel.setPreferredSize(new Dimension(70, 0));
        headerArea = new JTextArea(5, 1);
        headerArea.setFont(new Font("Monospaced", Font.PLAIN, 13));
        headerArea.setLineWrap(true);
        headerArea.setWrapStyleWord(true);
        headerPanel.add(headerLabel, BorderLayout.WEST);
        headerPanel.add(new JScrollPane(headerArea), BorderLayout.CENTER);
        gbc.gridx = 0; gbc.gridy = 0;
        gbc.weighty = 0.25;
        panel.add(headerPanel, gbc);
        
        // Payload - 标签和输入框在同一行
        JPanel payloadPanel = new JPanel(new BorderLayout(5, 0));
        JLabel payloadLabel = new JLabel("Payload:");
        payloadLabel.setFont(new Font("微软雅黑", Font.BOLD, 14));
        payloadLabel.setPreferredSize(new Dimension(70, 0));
        payloadArea = new JTextArea(5, 1);
        payloadArea.setFont(new Font("Monospaced", Font.PLAIN, 13));
        payloadArea.setLineWrap(true);
        payloadArea.setWrapStyleWord(true);
        payloadPanel.add(payloadLabel, BorderLayout.WEST);
        payloadPanel.add(new JScrollPane(payloadArea), BorderLayout.CENTER);
        gbc.gridx = 0; gbc.gridy = 1;
        gbc.weighty = 0.25;
        panel.add(payloadPanel, gbc);
        
        // Verify - 标签和输入框在同一行
        JPanel verifyPanel = new JPanel(new BorderLayout(5, 0));
        JLabel verifyLabel = new JLabel("Verify:");
        verifyLabel.setFont(new Font("微软雅黑", Font.BOLD, 14));
        verifyLabel.setPreferredSize(new Dimension(70, 0));
        verifyField = new JTextField();
        verifyField.setFont(new Font("Monospaced", Font.PLAIN, 13));
        verifyPanel.add(verifyLabel, BorderLayout.WEST);
        verifyPanel.add(verifyField, BorderLayout.CENTER);
        gbc.gridx = 0; gbc.gridy = 2;
        gbc.weighty = 0.15;
        panel.add(verifyPanel, gbc);
        
        // Secret - 标签和输入框在同一行
        JPanel secretPanel = new JPanel(new BorderLayout(5, 0));
        JLabel secretLabel = new JLabel("Secret:");
        secretLabel.setFont(new Font("微软雅黑", Font.BOLD, 14));
        secretLabel.setPreferredSize(new Dimension(70, 0));
        secretField = new JTextField();
        secretField.setFont(new Font("Monospaced", Font.PLAIN, 13));
        secretPanel.add(secretLabel, BorderLayout.WEST);
        secretPanel.add(secretField, BorderLayout.CENTER);
        gbc.gridx = 0; gbc.gridy = 3;
        gbc.weighty = 0.15;
        panel.add(secretPanel, gbc);
        
        // 爆破设置
        JPanel attackPanel = createAttackPanel();
        gbc.gridx = 0; gbc.gridy = 4;
        gbc.gridwidth = 1;
        gbc.weighty = 0.2;
        panel.add(attackPanel, gbc);
        
        return panel;
    }
    
    private JPanel createAttackPanel()
    {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder("爆破设置"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        
        // 第一行：编码类型、开始爆破、停止按钮
        gbc.gridx = 0; gbc.gridy = 0;
        panel.add(new JLabel("编码类型:"), gbc);
        
        encodingCombo = new JComboBox<>(new String[]{"ALL", "None", "Base64", "MD5", "MD5_16"});
        encodingCombo.setPreferredSize(new Dimension(90, 28));
        gbc.gridx = 1; gbc.gridy = 0;
        panel.add(encodingCombo, gbc);
        
        startBtn = new JButton("开始爆破");
        startBtn.setFont(new Font("微软雅黑", Font.BOLD, 13));
        startBtn.setPreferredSize(new Dimension(100, 32));
        startBtn.setBackground(new Color(76, 175, 80));
        startBtn.setForeground(Color.WHITE);
        startBtn.addActionListener(e -> startAttack());
        
        stopBtn = new JButton("停止");
        stopBtn.setFont(new Font("微软雅黑", Font.BOLD, 13));
        stopBtn.setPreferredSize(new Dimension(70, 32));
        stopBtn.setBackground(new Color(244, 67, 54));
        stopBtn.setForeground(Color.WHITE);
        stopBtn.setEnabled(false);
        stopBtn.addActionListener(e -> stopAttack());
        
        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 3, 0));
        btnPanel.add(startBtn);
        btnPanel.add(stopBtn);
        
        gbc.gridx = 2; gbc.gridy = 0;
        gbc.gridwidth = 2;
        panel.add(btnPanel, gbc);
        
        // 第二行：字典路径输入框、选择字典按钮
        gbc.gridwidth = 1;
        gbc.gridx = 0; gbc.gridy = 1;
        panel.add(new JLabel("字典路径:"), gbc);
        
        dictPathField = new JTextField();
        dictPathField.setFont(new Font("Monospaced", Font.PLAIN, 12));
        dictPathField.setEditable(false);
        dictPathField.setBackground(new Color(245, 245, 245));
        gbc.gridx = 1; gbc.gridy = 1;
        gbc.weightx = 1.0;
        panel.add(dictPathField, gbc);
        
        selectDictBtn = new JButton("选择字典");
        selectDictBtn.setPreferredSize(new Dimension(90, 28));
        selectDictBtn.addActionListener(e -> selectDictionary());
        gbc.gridx = 2; gbc.gridy = 1;
        gbc.weightx = 0;
        panel.add(selectDictBtn, gbc);
        
        // 进度条
        progressBar = new JProgressBar(0, 100);
        progressBar.setStringPainted(true);
        progressBar.setPreferredSize(new Dimension(0, 25));
        gbc.gridx = 0; gbc.gridy = 2;
        gbc.gridwidth = 3;
        panel.add(progressBar, gbc);
        
        return panel;
    }
    
    private JPanel createBottomPanel()
    {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("结果"));
        panel.setPreferredSize(new Dimension(0, 100));
        
        resultArea = new JTextArea(4, 1);
        resultArea.setFont(new Font("Monospaced", Font.PLAIN, 13));
        resultArea.setEditable(false);
        resultArea.setLineWrap(true);
        
        panel.add(new JScrollPane(resultArea), BorderLayout.CENTER);
        
        return panel;
    }
    
    private void parseJwtFromRequest(IHttpRequestResponse httpRequestResponse)
    {
        String jwt = extractJwt(httpRequestResponse);
        if (jwt != null) {
            jwtInputArea.setText(jwt);
            parseJwt(jwt);
        } else {
            resultArea.setText("未识别到JWT，请手动输入");
        }
    }
    
    private String extractJwt(IHttpRequestResponse httpRequestResponse)
    {
        String request = helpers.bytesToString(httpRequestResponse.getRequest());
        
        Pattern bearerPattern = Pattern.compile("[Bb]earer\\s+([A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]*)");
        Matcher bearerMatcher = bearerPattern.matcher(request);
        if (bearerMatcher.find()) return bearerMatcher.group(1);
        
        Pattern tokenPattern = Pattern.compile("[Tt]oken[=:]\\s*([A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]*)");
        Matcher tokenMatcher = tokenPattern.matcher(request);
        if (tokenMatcher.find()) return tokenMatcher.group(1);
        
        Pattern authPattern = Pattern.compile("[Aa]uthorization[=:]\\s*([A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]*)");
        Matcher authMatcher = authPattern.matcher(request);
        if (authMatcher.find()) return authMatcher.group(1);
        
        Pattern jwtPattern = Pattern.compile("([A-Za-z0-9-_]{10,}\\.[A-Za-z0-9-_]{10,}\\.[A-Za-z0-9-_]*)");
        Matcher jwtMatcher = jwtPattern.matcher(request);
        if (jwtMatcher.find()) return jwtMatcher.group(1);
        
        return null;
    }
    
    private void parseJwt(String jwt)
    {
        try {
            String[] parts = jwt.split("\\.");
            if (parts.length != 3) {
                resultArea.setText("无效JWT格式");
                return;
            }
            
            originalHeaderBase64 = parts[0];
            originalPayloadBase64 = parts[1];
            
            String headerJson = decodeBase64Url(parts[0]);
            headerArea.setText(formatJson(headerJson));
            
            byte[] payloadBytes = decodeBase64UrlBytes(parts[1]);
            String payloadStr = decompressPayload(payloadBytes, headerJson);
            payloadArea.setText(formatJson(payloadStr));
            
            verifyField.setText(parts[2]);
            
            Pattern algPattern = Pattern.compile("\"alg\"\\s*:\\s*\"([^\"]+)\"");
            Matcher algMatcher = algPattern.matcher(headerArea.getText());
            if (algMatcher.find()) {
                currentAlgorithm = algMatcher.group(1);
                algorithmCombo.setSelectedItem(currentAlgorithm);
            }
            
            resultArea.setText("解析成功，当前算法: " + currentAlgorithm);
        } catch (Exception e) {
            resultArea.setText("解析失败: " + e.getMessage());
        }
    }
    
    private byte[] decodeBase64UrlBytes(String input)
    {
        String base64 = input.replace('-', '+').replace('_', '/');
        switch (base64.length() % 4) {
            case 2: base64 += "=="; break;
            case 3: base64 += "="; break;
        }
        return Base64.getDecoder().decode(base64);
    }
    
    private String decompressPayload(byte[] payloadBytes, String headerJson)
    {
        Pattern zipPattern = Pattern.compile("\"zip\"\\s*:\\s*\"([^\"]+)\"", Pattern.CASE_INSENSITIVE);
        Matcher zipMatcher = zipPattern.matcher(headerJson);
        
        if (zipMatcher.find()) {
            String zipAlgo = zipMatcher.group(1).toUpperCase();
            if ("GZIP".equals(zipAlgo)) {
                try {
                    GZIPInputStream gis = new GZIPInputStream(
                        new java.io.ByteArrayInputStream(payloadBytes));
                    java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
                    byte[] buffer = new byte[4096];
                    int len;
                    while ((len = gis.read(buffer)) > 0) {
                        baos.write(buffer, 0, len);
                    }
                    gis.close();
                    return baos.toString(StandardCharsets.UTF_8);
                } catch (Exception e) {
                    return "[GZIP解压失败] " + new String(payloadBytes, StandardCharsets.ISO_8859_1);
                }
            } else if ("DEF".equals(zipAlgo) || "DEFLATE".equals(zipAlgo)) {
                try {
                    java.util.zip.Inflater inf = new java.util.zip.Inflater(true);
                    inf.setInput(payloadBytes);
                    byte[] result = new byte[4096];
                    int len = inf.inflate(result);
                    inf.end();
                    return new String(result, 0, len, StandardCharsets.UTF_8);
                } catch (Exception e) {
                    return "[DEF解压失败] " + new String(payloadBytes, StandardCharsets.ISO_8859_1);
                }
            }
        }
        return new String(payloadBytes, StandardCharsets.UTF_8);
    }
    
    private String decodeBase64Url(String input)
    {
        String base64 = input.replace('-', '+').replace('_', '/');
        switch (base64.length() % 4) {
            case 2: base64 += "=="; break;
            case 3: base64 += "="; break;
        }
        return new String(Base64.getDecoder().decode(base64));
    }
    
    private String formatJson(String json)
    {
        StringBuilder sb = new StringBuilder();
        int indent = 0;
        boolean inString = false;
        
        for (int i = 0; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '"' && (i == 0 || json.charAt(i-1) != '\\')) {
                inString = !inString;
                sb.append(c);
            } else if (!inString) {
                if (c == '{' || c == '[') {
                    sb.append(c).append('\n');
                    indent += 2;
                    sb.append("  ".repeat(indent / 2));
                } else if (c == '}' || c == ']') {
                    sb.append('\n');
                    indent -= 2;
                    sb.append("  ".repeat(indent / 2)).append(c);
                } else if (c == ',') {
                    sb.append(c).append('\n').append("  ".repeat(indent / 2));
                } else if (c == ':') {
                    sb.append(c).append(' ');
                } else if (c != ' ' && c != '\n' && c != '\r' && c != '\t') {
                    sb.append(c);
                }
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }
    
    private void decodeJwt()
    {
        String jwt = jwtInputArea.getText().trim();
        if (jwt.isEmpty()) {
            resultArea.setText("请输入JWT");
            return;
        }
        parseJwt(jwt);
    }
    
    private void encodeJwt()
    {
        try {
            String header = compressJson(headerArea.getText());
            String secret = secretField.getText().trim();
            String algorithm = (String) algorithmCombo.getSelectedItem();
            
            if (header.isEmpty()) {
                resultArea.setText("Header不能为空");
                return;
            }
            
            String headerBase64 = encodeBase64Url(header);
            
            String payloadBase64;
            String payload = compressJson(payloadArea.getText());
            
            if (payload.isEmpty()) {
                resultArea.setText("Payload不能为空");
                return;
            }
            
            Pattern zipPattern = Pattern.compile("\"zip\"\\s*:\\s*\"([^\"]+)\"", Pattern.CASE_INSENSITIVE);
            Matcher zipMatcher = zipPattern.matcher(header);
            
            if (zipMatcher.find()) {
                String zipAlgo = zipMatcher.group(1).toUpperCase();
                byte[] compressed = compressPayload(payload, zipAlgo);
                payloadBase64 = encodeBase64UrlBytes(compressed);
            } else {
                payloadBase64 = encodeBase64Url(payload);
            }
            
            String signature = "";
            if (!secret.isEmpty() && !"None".equals(algorithm)) {
                signature = generateSignature(headerBase64 + "." + payloadBase64, secret, algorithm);
            }
            
            jwtInputArea.setText(headerBase64 + "." + payloadBase64 + "." + signature);
            verifyField.setText(signature);
            resultArea.setText("编码成功");
        } catch (Exception e) {
            resultArea.setText("编码失败: " + e.getMessage());
        }
    }
    
    private String compressJson(String json)
    {
        StringBuilder sb = new StringBuilder();
        for (char c : json.toCharArray()) {
            if (c != ' ' && c != '\n' && c != '\r' && c != '\t') {
                sb.append(c);
            }
        }
        return sb.toString();
    }
    
    private void verifySignature()
    {
        try {
            String jwt = jwtInputArea.getText().trim();
            if (jwt.isEmpty()) {
                resultArea.setText("请输入JWT");
                return;
            }
            
            String[] parts = jwt.split("\\.");
            if (parts.length != 3) {
                resultArea.setText("无效JWT格式");
                return;
            }
            
            headerArea.setText(formatJson(decodeBase64Url(parts[0])));
            payloadArea.setText(formatJson(decodeBase64Url(parts[1])));
            verifyField.setText(parts[2]);
            
            String secret = secretField.getText().trim();
            if (secret.isEmpty()) {
                resultArea.setText("请输入Secret进行校验");
                return;
            }
            
            String algorithm = (String) algorithmCombo.getSelectedItem();
            String expected = generateSignature(parts[0] + "." + parts[1], secret, algorithm);
            
            if (expected.equals(parts[2])) {
                resultArea.setText("✓ 校验成功！密钥: " + secret);
            } else {
                resultArea.setText("✗ 校验失败");
            }
        } catch (Exception e) {
            resultArea.setText("校验失败: " + e.getMessage());
        }
    }
    
    private String encodeBase64Url(String input)
    {
        String base64 = Base64.getEncoder().encodeToString(input.getBytes(StandardCharsets.UTF_8));
        return base64.replace('+', '-').replace('/', '_').replace("=", "");
    }
    
    private String encodeBase64UrlBytes(byte[] input)
    {
        String base64 = Base64.getEncoder().encodeToString(input);
        return base64.replace('+', '-').replace('/', '_').replace("=", "");
    }
    
    private byte[] compressPayload(String payload, String zipAlgo) throws Exception
    {
        if ("GZIP".equals(zipAlgo)) {
            java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
            java.util.zip.GZIPOutputStream gzip = new java.util.zip.GZIPOutputStream(baos);
            gzip.write(payload.getBytes(StandardCharsets.UTF_8));
            gzip.close();
            return baos.toByteArray();
        } else if ("DEF".equals(zipAlgo) || "DEFLATE".equals(zipAlgo)) {
            java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
            java.util.zip.Deflater deflater = new java.util.zip.Deflater();
            deflater.setInput(payload.getBytes(StandardCharsets.UTF_8));
            deflater.finish();
            byte[] buffer = new byte[4096];
            while (!deflater.finished()) {
                int count = deflater.deflate(buffer);
                baos.write(buffer, 0, count);
            }
            deflater.end();
            return baos.toByteArray();
        }
        return payload.getBytes(StandardCharsets.UTF_8);
    }
    
    private String generateSignature(String data, String key, String algorithm)
    {
        if (algorithm == null || "None".equals(algorithm)) return "";
        
        try {
            if (algorithm.startsWith("HS")) {
                return generateHmacSignature(data, key.getBytes(StandardCharsets.UTF_8), algorithm);
            }
            else if (algorithm.startsWith("RS") || algorithm.startsWith("PS")) {
                return signWithRSA(data, key, algorithm);
            }
            else if (algorithm.startsWith("ES")) {
                return signWithECDSA(data, key, algorithm);
            }
            else if ("EdDSA".equals(algorithm)) {
                return signWithEdDSA(data, key);
            }
            return "";
        } catch (Exception e) {
            return "";
        }
    }

    private String generateHmacSignature(String data, byte[] keyBytes, String algorithm)
    {
        try {
            String alg = algorithm.replace("HS256", "HmacSHA256")
                                 .replace("HS384", "HmacSHA384")
                                 .replace("HS512", "HmacSHA512");
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance(alg);
            mac.init(new javax.crypto.spec.SecretKeySpec(keyBytes, alg));
            byte[] hmac = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            String sig = Base64.getEncoder().encodeToString(hmac);
            return sig.replace('+', '-').replace('/', '_').replace("=", "");
        } catch (Exception e) {
            return "";
        }
    }

    private byte[] decodeBase64Flexible(String value)
    {
        String normalized = value.trim().replaceAll("\\s+", "")
                               .replace('-', '+').replace('_', '/');
        switch (normalized.length() % 4) {
            case 2: normalized += "=="; break;
            case 3: normalized += "="; break;
            case 1: return null;
        }
        try {
            return Base64.getDecoder().decode(normalized);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
    
    private String signWithRSA(String data, String privateKeyPEM, String algorithm) throws Exception {
        String alg = algorithm.replace("RS256", "SHA256withRSA")
                             .replace("RS384", "SHA384withRSA")
                             .replace("RS512", "SHA512withRSA")
                             .replace("PS256", "SHA256withRSA")
                             .replace("PS384", "SHA384withRSA")
                             .replace("PS512", "SHA512withRSA");
        
        byte[] keyBytes = parsePEM(privateKeyPEM);
        java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
        java.security.PrivateKey privateKey = keyFactory.generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(keyBytes));
        
        java.security.Signature sig = java.security.Signature.getInstance(alg);
        sig.initSign(privateKey);
        sig.update(data.getBytes());
        byte[] signature = sig.sign();
        String result = Base64.getEncoder().encodeToString(signature);
        return result.replace('+', '-').replace('/', '_').replace("=", "");
    }
    
    private String signWithECDSA(String data, String privateKeyPEM, String algorithm) throws Exception {
        String alg = algorithm.replace("ES256", "SHA256withECDSA")
                             .replace("ES384", "SHA384withECDSA")
                             .replace("ES512", "SHA512withECDSA");
        
        byte[] keyBytes = parsePEM(privateKeyPEM);
        java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("EC");
        java.security.PrivateKey privateKey = keyFactory.generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(keyBytes));
        
        java.security.Signature sig = java.security.Signature.getInstance(alg);
        sig.initSign(privateKey);
        sig.update(data.getBytes());
        byte[] signature = sig.sign();
        
        if (algorithm.endsWith("256") || algorithm.endsWith("384")) {
            signature = convertDERtoJWS(signature, algorithm);
        }
        
        String result = Base64.getEncoder().encodeToString(signature);
        return result.replace('+', '-').replace('/', '_').replace("=", "");
    }
    
    private byte[] convertDERtoJWS(byte[] derSignature, String algorithm) {
        int len = derSignature.length;
        int off = 0;
        if (derSignature[off++] != 0x30) return derSignature;
        
        int totalLen = len - off;
        if (derSignature[off++] != totalLen) return derSignature;
        
        int rLen = derSignature[off++];
        int rStart = off;
        off += rLen;
        
        int sLen = derSignature[off++];
        int sStart = off;
        
        int keyLen = 32;
        if (algorithm.endsWith("384")) keyLen = 48;
        if (algorithm.endsWith("512")) keyLen = 66;
        
        byte[] jwsSig = new byte[keyLen * 2];
        System.arraycopy(derSignature, rStart, jwsSig, keyLen - (rLen - 2), rLen - 2);
        System.arraycopy(derSignature, sStart, jwsSig, keyLen * 2 - (sLen - 2), sLen - 2);
        
        return jwsSig;
    }
    
    private String signWithEdDSA(String data, String privateKeyPEM) throws Exception {
        byte[] keyBytes = parsePEM(privateKeyPEM);
        java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("EdDSA");
        java.security.PrivateKey privateKey = keyFactory.generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(keyBytes));
        
        java.security.Signature sig = java.security.Signature.getInstance("EdDSA");
        sig.initSign(privateKey);
        sig.update(data.getBytes());
        byte[] signature = sig.sign();
        
        String result = Base64.getEncoder().encodeToString(signature);
        return result.replace('+', '-').replace('/', '_').replace("=", "");
    }
    
    private byte[] parsePEM(String pem) throws Exception {
        pem = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                 .replace("-----END PRIVATE KEY-----", "")
                 .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                 .replace("-----END RSA PRIVATE KEY-----", "")
                 .replace("-----BEGIN EC PRIVATE KEY-----", "")
                 .replace("-----END EC PRIVATE KEY-----", "")
                 .replace("-----BEGIN OPENSSH PRIVATE KEY-----", "")
                 .replace("-----END OPENSSH PRIVATE KEY-----", "")
                 .replaceAll("\\s", "");
        return Base64.getDecoder().decode(pem);
    }
    
    private void clearFields()
    {
        jwtInputArea.setText("");
        headerArea.setText("");
        payloadArea.setText("");
        verifyField.setText("");
        secretField.setText("");
        originalHeaderBase64 = null;
        originalPayloadBase64 = null;
    }
    
    private void selectDictionary()
    {
        JFileChooser fileChooser = new JFileChooser();
        if (fileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
            selectedWordlistPath = fileChooser.getSelectedFile().getAbsolutePath();
            dictPathField.setText(selectedWordlistPath);
            wordlist.clear();
            try {
                java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.FileReader(selectedWordlistPath));
                String line;
                while ((line = reader.readLine()) != null) wordlist.add(line);
                reader.close();
                resultArea.setText("已加载: " + selectedWordlistPath + " (" + wordlist.size() + "个)");
            } catch (Exception e) {
                resultArea.setText("加载失败: " + e.getMessage());
            }
        }
    }
    
    private void loadBuiltInDict(IBurpExtenderCallbacks callbacks)
    {
        wordlist.clear();
        boolean loaded = false;
        
        try {
            java.io.InputStream is = getClass().getClassLoader().getResourceAsStream("resources/wordlist.txt");
            if (is != null) {
                java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.InputStreamReader(is));
                String line;
                while ((line = reader.readLine()) != null) {
                    if (!line.trim().isEmpty()) wordlist.add(line.trim());
                }
                reader.close();
                
                if (!wordlist.isEmpty()) {
                    java.io.File extDir = new java.io.File(callbacks.getExtensionFilename()).getParentFile();
                    java.io.File dictFile = new java.io.File(extDir, "wordlist.txt");
                    
                    if (!dictFile.exists()) {
                        java.io.FileOutputStream fos = new java.io.FileOutputStream(dictFile);
                        byte[] buffer = new byte[4096];
                        int len;
                        is = getClass().getClassLoader().getResourceAsStream("resources/wordlist.txt");
                        while ((len = is.read(buffer)) > 0) {
                            fos.write(buffer, 0, len);
                        }
                        is.close();
                        fos.close();
                    }
                    
                    dictPathField.setText(dictFile.getAbsolutePath());
                    selectedWordlistPath = dictFile.getAbsolutePath();
                    loaded = true;
                }
            }
        } catch (Exception e) {
        }
        
        if (!loaded) {
            for (String word : builtInWords) wordlist.add(word);
            dictPathField.setText("(无内置字典文件)");
            selectedWordlistPath = "";
        }
        
        resultArea.setText("已加载字典 (" + wordlist.size() + "个)");
    }
    
    private void loadDictionaryFromPath(String path)
    {
        selectedWordlistPath = path;
        dictPathField.setText(path);
        wordlist.clear();
        try {
            java.io.BufferedReader reader = new java.io.BufferedReader(
                new java.io.FileReader(path));
            String line;
            while ((line = reader.readLine()) != null) wordlist.add(line);
            reader.close();
            resultArea.setText("已加载: " + path + " (" + wordlist.size() + "个)");
        } catch (Exception e) {
            resultArea.setText("加载失败: " + e.getMessage());
        }
    }
    
    private void startAttack()
    {
        if (wordlist.isEmpty()) {
            JOptionPane.showMessageDialog(null, "请先加载字典");
            return;
        }
        if (!currentAlgorithm.startsWith("HS")) {
            JOptionPane.showMessageDialog(null, "仅支持HS系列算法");
            return;
        }
        if (originalHeaderBase64 == null || originalPayloadBase64 == null) {
            JOptionPane.showMessageDialog(null, "请先解码JWT");
            return;
        }
        
        isRunning.set(true);
        startBtn.setEnabled(false);
        stopBtn.setEnabled(true);
        progressBar.setValue(0);
        resultArea.setText("开始爆破...");
        
        String verifySig = verifyField.getText().trim();
        
        executor.execute(() -> {
            try {
                String encoding = (String) encodingCombo.getSelectedItem();
                String[] encodings;
                if ("ALL".equals(encoding)) {
                    encodings = new String[]{"None", "Base64", "MD5", "MD5_16"};
                } else {
                    encodings = new String[]{encoding};
                }
                
                int totalWords = 0;
                for (String enc : encodings) {
                    totalWords += getTestWords(enc).size();
                }
                
                int processedWords = 0;
                
                for (String enc : encodings) {
                    if (!isRunning.get()) break;
                    
                    List<String> testWords = getTestWords(enc);
                    for (int i = 0; i < testWords.size() && isRunning.get(); i++) {
                        String secret = testWords.get(i);
                        String data = originalHeaderBase64 + "." + originalPayloadBase64;
                        String signature;
                        String displaySecret = secret;
                        String foundEncoding = enc;

                        if ("Base64".equals(enc)) {
                            String encodedCandidate = base64(secret);
                            signature = generateSignature(data, encodedCandidate, currentAlgorithm);
                            if (!signature.equals(verifySig)) {
                                byte[] decodedBytes = decodeBase64Flexible(secret);
                                if (decodedBytes != null) {
                                    signature = generateHmacSignature(data, decodedBytes, currentAlgorithm);
                                    if (signature.equals(verifySig)) {
                                        displaySecret = secret;
                                        foundEncoding = "Base64(Decode)";
                                    }
                                }
                            } else {
                                displaySecret = encodedCandidate;
                                foundEncoding = "Base64(Encode)";
                            }
                        } else {
                            signature = generateSignature(data, secret, currentAlgorithm);
                        }
                        
                        processedWords++;
                        int progress = (int) (processedWords * 100.0 / totalWords);
                        SwingUtilities.invokeLater(() -> progressBar.setValue(progress));
                        
                        if (signature.equals(verifySig)) {
                            final String finalFoundEncoding = foundEncoding;
                            final String finalDisplaySecret = displaySecret;
                            SwingUtilities.invokeLater(() -> {
                                secretField.setText(finalDisplaySecret);
                                encodingCombo.setSelectedItem(enc);
                                resultArea.setText("[成功] 密钥: " + finalDisplaySecret + " (编码: " + finalFoundEncoding + ")");
                            });
                            isRunning.set(false);
                            break;
                        }
                    }
                }
                if (isRunning.get()) {
                    SwingUtilities.invokeLater(() -> 
                        resultArea.setText(resultArea.getText() + " 未找到"));
                }
            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> 
                    resultArea.setText("出错: " + e.getMessage()));
            } finally {
                SwingUtilities.invokeLater(() -> {
                    startBtn.setEnabled(true);
                    stopBtn.setEnabled(false);
                });
            }
        });
    }
    
    private List<String> getTestWords(String encoding)
    {
        List<String> result = new ArrayList<>();
        if ("ALL".equals(encoding)) {
            for (String word : wordlist) {
                result.add(word);
                result.add(base64(word));
                result.add(md5(word));
                result.add(md5(word).substring(0, 16));
            }
        } else if ("None".equals(encoding)) {
            result.addAll(wordlist);
        } else if ("Base64".equals(encoding)) {
            result.addAll(wordlist);
        } else if ("MD5".equals(encoding)) {
            for (String word : wordlist) result.add(md5(word));
        } else if ("MD5_16".equals(encoding)) {
            for (String word : wordlist) result.add(md5(word).substring(0, 16));
        }
        return result;
    }
    
    private String base64(String input)
    {
        return Base64.getEncoder().encodeToString(input.getBytes(StandardCharsets.UTF_8));
    }
    
    private String md5(String input)
    {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) sb.append('0');
                sb.append(hex);
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }
    
    private void stopAttack()
    {
        isRunning.set(false);
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation)
    {
        List<JMenuItem> menuItems = new ArrayList<>();
        JMenuItem menuItem = new JMenuItem("Send to JWT Tool");
        menuItem.addActionListener(e -> {
            IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();
            if (selectedMessages != null) {
                for (IHttpRequestResponse msg : selectedMessages) {
                    httpMessages.add(msg);
                    listModel.addElement(helpers.analyzeRequest(msg).getMethod() + " " + 
                                        helpers.analyzeRequest(msg).getUrl().getPath());
                }
            }
        });
        menuItems.add(menuItem);
        return menuItems;
    }

    @Override
    public String getTabCaption() { return "JWT Tool"; }

    @Override
    public Component getUiComponent() { return mainPanel; }
}
