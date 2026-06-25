# -*- coding: utf-8 -*-
# ai_analyzer.py
# Burp Suite Plugin - AI Security Analyzer (Dark Theme with Persian Support)

from burp import IBurpExtender, IContextMenuFactory, ITab
from javax.swing import (JPanel, JTextArea, JButton, JScrollPane, JLabel, JSplitPane,
                         JCheckBox, SwingUtilities, JMenu, JMenuItem, JDialog,
                         BorderFactory, JTextField, JPasswordField)
from java.awt import (BorderLayout, FlowLayout, Dimension, Color, Font,
                      ComponentOrientation, GridBagLayout, GridBagConstraints, Insets)
from java.awt.event import ActionListener, ItemListener
from java.net import URL, HttpURLConnection
from java.io import BufferedReader, InputStreamReader, OutputStreamWriter
from threading import Thread
import json
import traceback

class BurpExtender(IBurpExtender, IContextMenuFactory, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("AI Security Analyzer")

        self.persianMode = False
        
        # Default values - exactly what worked before
        self.DEFAULT_API_URL = "https://api.openmodel.ai/v1/messages"
        self.DEFAULT_API_KEY = "om-teeeeeeeeeeeeeeeeest"
        self.DEFAULT_MODEL = "deepseek-v4-flash"
        self.DEFAULT_MAX_TOKENS = 10000

        # Load saved settings or use defaults
        savedUrl = self._callbacks.loadExtensionSetting("apiUrl")
        self.API_URL = savedUrl if savedUrl else self.DEFAULT_API_URL
        
        savedKey = self._callbacks.loadExtensionSetting("apiKey")
        self.API_KEY = savedKey if savedKey else self.DEFAULT_API_KEY
        
        savedModel = self._callbacks.loadExtensionSetting("model")
        self.MODEL = savedModel if savedModel else self.DEFAULT_MODEL
        
        savedTokens = self._callbacks.loadExtensionSetting("maxTokens")
        if savedTokens:
            try:
                self.MAX_TOKENS = int(savedTokens)
            except:
                self.MAX_TOKENS = self.DEFAULT_MAX_TOKENS
        else:
            self.MAX_TOKENS = self.DEFAULT_MAX_TOKENS

        # Load saved prompts or use defaults
        self.promptEnglish = self._callbacks.loadExtensionSetting("promptEnglish")
        if self.promptEnglish is None:
            self.promptEnglish = (
                "As a legal pentester, analyze this and tell me what interesting things "
                "you see that would be valuable for a pentester. Please provide your "
                "response in English:\n\n```\n{REQUEST}\n```\n\nWhat security issues "
                "or interesting findings do you see? Please respond in English only."
            )

        self.promptPersian = self._callbacks.loadExtensionSetting("promptPersian")
        if self.promptPersian is None:
            self.promptPersian = (
                "As a legal pentester, analyze this and tell me what interesting things "
                "you see that would be valuable for a pentester. Please provide your "
                "response in Persian (Farsi) language:\n\n```\n{REQUEST}\n```\n\nWhat "
                "security issues or interesting findings do you see? Please respond in "
                "Persian (Farsi) only. Keep the technical terms in English if needed, "
                "but explain everything in Persian."
            )

        self.initUI()
        callbacks.registerContextMenuFactory(self)

        print("[+] AI Security Analyzer loaded successfully!")
        print("[+] API URL: " + self.API_URL)
        print("[+] Model: " + self.MODEL)
        print("[+] Right-click menu registered for Proxy, Repeater, Target, etc.")

    def initUI(self):
        self.BG_COLOR = Color(30, 30, 35)
        self.TEXT_COLOR = Color(220, 220, 230)
        self.ACCENT_COLOR = Color(70, 130, 220)
        self.GREEN_COLOR = Color(80, 180, 80)
        self.ORANGE_COLOR = Color(220, 150, 50)
        self.PURPLE_COLOR = Color(150, 100, 220)
        self.PANEL_COLOR = Color(40, 40, 45)
        self.BORDER_COLOR = Color(60, 60, 70)
        self.INPUT_COLOR = Color(50, 50, 55)
        self.OUTPUT_COLOR = Color(25, 30, 40)

        self.monoFont = Font("Monospaced", Font.PLAIN, 13)
        self.sansFont = Font("SansSerif", Font.PLAIN, 13)

        self.mainPanel = JPanel(BorderLayout())
        self.mainPanel.setBackground(self.BG_COLOR)
        self.mainPanel.setPreferredSize(Dimension(900, 700))

        splitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        splitPane.setResizeWeight(0.5)
        splitPane.setBackground(self.BG_COLOR)
        splitPane.setBorder(BorderFactory.createLineBorder(self.BORDER_COLOR))

        # ---------- Top: Request Panel ----------
        requestPanel = JPanel(BorderLayout())
        requestPanel.setBackground(self.PANEL_COLOR)
        requestPanel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(self.ACCENT_COLOR, 1),
            " Request to Analyze "
        ))

        self.requestText = JTextArea(10, 60)
        self.requestText.setBackground(self.INPUT_COLOR)
        self.requestText.setForeground(self.TEXT_COLOR)
        self.requestText.setCaretColor(self.TEXT_COLOR)
        self.requestText.setFont(self.monoFont)
        self.requestText.setLineWrap(True)
        self.requestText.setWrapStyleWord(True)
        self.requestText.setText("GET / HTTP/1.1\nHost: example.com\n\n")
        self.requestText.setBorder(BorderFactory.createLineBorder(self.BORDER_COLOR, 1))

        requestScroll = JScrollPane(self.requestText)
        requestScroll.setBackground(self.INPUT_COLOR)
        requestScroll.setBorder(BorderFactory.createLineBorder(self.BORDER_COLOR, 1))
        requestPanel.add(requestScroll, BorderLayout.CENTER)

        # Button panel
        buttonPanel = JPanel(FlowLayout(FlowLayout.LEFT, 5, 5))
        buttonPanel.setBackground(self.PANEL_COLOR)

        self.sendBtn = self.createStyledButton("Send to AI", self.GREEN_COLOR, Color.WHITE)
        self.sendBtn.addActionListener(self.sendRequest)

        clearBtn = self.createStyledButton("Clear", Color(100, 100, 110), self.TEXT_COLOR)
        clearBtn.addActionListener(self.clearResponse)

        loadBtn = self.createStyledButton("Load from Proxy", Color(100, 100, 110), self.TEXT_COLOR)
        loadBtn.addActionListener(self.loadFromProxy)

        self.persianCheckbox = JCheckBox("Persian (Farsi)", False)
        self.persianCheckbox.setBackground(self.PANEL_COLOR)
        self.persianCheckbox.setForeground(self.TEXT_COLOR)
        self.persianCheckbox.setFont(self.sansFont)
        self.persianCheckbox.addItemListener(self.onPersianToggle)

        editPromptsBtn = self.createStyledButton("Edit Prompts", self.ORANGE_COLOR, Color.BLACK)
        editPromptsBtn.addActionListener(self.showPromptEditor)

        settingsBtn = self.createStyledButton("Settings", self.PURPLE_COLOR, Color.WHITE)
        settingsBtn.addActionListener(self.showSettings)

        buttonPanel.add(self.sendBtn)
        buttonPanel.add(clearBtn)
        buttonPanel.add(loadBtn)
        buttonPanel.add(self.persianCheckbox)
        buttonPanel.add(editPromptsBtn)
        buttonPanel.add(settingsBtn)

        self.statusLabel = JLabel("Ready")
        self.statusLabel.setForeground(Color(100, 200, 100))
        self.statusLabel.setFont(self.sansFont)
        buttonPanel.add(self.statusLabel)

        requestPanel.add(buttonPanel, BorderLayout.SOUTH)

        # ---------- Bottom: Response Panel ----------
        responsePanel = JPanel(BorderLayout())
        responsePanel.setBackground(self.PANEL_COLOR)
        responsePanel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(self.GREEN_COLOR, 1),
            " AI Analysis Result "
        ))

        self.responseText = JTextArea(12, 60)
        self.responseText.setBackground(self.OUTPUT_COLOR)
        self.responseText.setForeground(Color(200, 220, 255))
        self.responseText.setCaretColor(self.TEXT_COLOR)
        self.responseText.setFont(self.monoFont)
        self.responseText.setLineWrap(True)
        self.responseText.setWrapStyleWord(True)
        self.responseText.setEditable(False)
        self.responseText.setBorder(BorderFactory.createLineBorder(self.BORDER_COLOR, 1))
        self.responseText.setText("Waiting for analysis...")
        self.responseText.setForeground(Color(150, 150, 170))
        self.responseText.setComponentOrientation(ComponentOrientation.LEFT_TO_RIGHT)

        responseScroll = JScrollPane(self.responseText)
        responseScroll.setBackground(self.OUTPUT_COLOR)
        responseScroll.setBorder(BorderFactory.createLineBorder(self.BORDER_COLOR, 1))
        responsePanel.add(responseScroll, BorderLayout.CENTER)

        splitPane.setTopComponent(requestPanel)
        splitPane.setBottomComponent(responsePanel)

        self.mainPanel.add(splitPane, BorderLayout.CENTER)

        self._callbacks.addSuiteTab(self)

    # ---------- Styled button creator ----------
    def createStyledButton(self, text, bgColor, fgColor):
        btn = JButton(text)
        btn.setBackground(bgColor)
        btn.setForeground(fgColor)
        btn.setFont(self.sansFont.deriveFont(Font.BOLD, 12))
        btn.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(bgColor.darker(), 2),
            BorderFactory.createEmptyBorder(6, 12, 6, 12)
        ))
        btn.setFocusPainted(False)
        return btn

    # ---------- Settings Dialog ----------
    def showSettings(self, event):
        try:
            dialog = JDialog(SwingUtilities.getWindowAncestor(self.mainPanel), "API Settings", True)
            dialog.setLayout(BorderLayout())
            dialog.setSize(600, 350)
            dialog.setLocationRelativeTo(self.mainPanel)

            mainPanel = JPanel(BorderLayout())
            mainPanel.setBackground(self.BG_COLOR)
            mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

            # Form panel
            formPanel = JPanel(GridBagLayout())
            formPanel.setBackground(self.BG_COLOR)
            c = GridBagConstraints()
            c.fill = GridBagConstraints.HORIZONTAL
            c.insets = Insets(5, 5, 5, 5)

            # API URL
            c.gridx = 0
            c.gridy = 0
            c.weightx = 0
            urlLabel = JLabel("API URL:")
            urlLabel.setForeground(self.TEXT_COLOR)
            urlLabel.setFont(self.sansFont)
            formPanel.add(urlLabel, c)

            c.gridx = 1
            c.weightx = 1.0
            self.apiUrlField = JTextField(self.API_URL, 40)
            self.apiUrlField.setBackground(self.INPUT_COLOR)
            self.apiUrlField.setForeground(self.TEXT_COLOR)
            self.apiUrlField.setCaretColor(self.TEXT_COLOR)
            self.apiUrlField.setFont(self.monoFont)
            formPanel.add(self.apiUrlField, c)

            # API Key
            c.gridx = 0
            c.gridy = 1
            c.weightx = 0
            keyLabel = JLabel("API Key:")
            keyLabel.setForeground(self.TEXT_COLOR)
            keyLabel.setFont(self.sansFont)
            formPanel.add(keyLabel, c)

            c.gridx = 1
            c.weightx = 1.0
            self.apiKeyField = JPasswordField(self.API_KEY, 40)
            self.apiKeyField.setBackground(self.INPUT_COLOR)
            self.apiKeyField.setForeground(self.TEXT_COLOR)
            self.apiKeyField.setCaretColor(self.TEXT_COLOR)
            self.apiKeyField.setFont(self.monoFont)
            formPanel.add(self.apiKeyField, c)

            # Model
            c.gridx = 0
            c.gridy = 2
            c.weightx = 0
            modelLabel = JLabel("Model:")
            modelLabel.setForeground(self.TEXT_COLOR)
            modelLabel.setFont(self.sansFont)
            formPanel.add(modelLabel, c)

            c.gridx = 1
            c.weightx = 1.0
            self.modelField = JTextField(self.MODEL, 40)
            self.modelField.setBackground(self.INPUT_COLOR)
            self.modelField.setForeground(self.TEXT_COLOR)
            self.modelField.setCaretColor(self.TEXT_COLOR)
            self.modelField.setFont(self.monoFont)
            formPanel.add(self.modelField, c)

            # Max Tokens
            c.gridx = 0
            c.gridy = 3
            c.weightx = 0
            tokensLabel = JLabel("Max Tokens:")
            tokensLabel.setForeground(self.TEXT_COLOR)
            tokensLabel.setFont(self.sansFont)
            formPanel.add(tokensLabel, c)

            c.gridx = 1
            c.weightx = 1.0
            self.maxTokensField = JTextField(str(self.MAX_TOKENS), 10)
            self.maxTokensField.setBackground(self.INPUT_COLOR)
            self.maxTokensField.setForeground(self.TEXT_COLOR)
            self.maxTokensField.setCaretColor(self.TEXT_COLOR)
            self.maxTokensField.setFont(self.monoFont)
            formPanel.add(self.maxTokensField, c)

            # Info label
            c.gridx = 0
            c.gridy = 4
            c.gridwidth = 2
            c.weightx = 1.0
            infoLabel = JLabel("<html><i>Settings are saved automatically and persist across Burp restarts.</i></html>")
            infoLabel.setForeground(Color(180, 180, 200))
            infoLabel.setFont(self.sansFont)
            formPanel.add(infoLabel, c)

            mainPanel.add(formPanel, BorderLayout.CENTER)

            # Buttons
            btnPanel = JPanel(FlowLayout(FlowLayout.RIGHT))
            btnPanel.setBackground(self.BG_COLOR)

            saveBtn = JButton("Save & Close")
            saveBtn.setBackground(self.GREEN_COLOR)
            saveBtn.setForeground(Color.WHITE)
            saveBtn.setFont(self.sansFont.deriveFont(Font.BOLD, 12))
            saveBtn.addActionListener(lambda e: self.saveSettings(dialog))

            cancelBtn = JButton("Cancel")
            cancelBtn.setBackground(Color(100, 100, 110))
            cancelBtn.setForeground(self.TEXT_COLOR)
            cancelBtn.setFont(self.sansFont.deriveFont(Font.BOLD, 12))
            cancelBtn.addActionListener(lambda e: dialog.dispose())

            testBtn = JButton("Test Connection")
            testBtn.setBackground(self.ACCENT_COLOR)
            testBtn.setForeground(Color.WHITE)
            testBtn.setFont(self.sansFont.deriveFont(Font.BOLD, 12))
            testBtn.addActionListener(lambda e: self.testApiConnection(dialog))

            btnPanel.add(testBtn)
            btnPanel.add(saveBtn)
            btnPanel.add(cancelBtn)
            mainPanel.add(btnPanel, BorderLayout.SOUTH)

            dialog.add(mainPanel)
            dialog.setVisible(True)
        except Exception as e:
            print("[ERROR] showSettings: " + str(e))
            traceback.print_exc()

    def saveSettings(self, dialog):
        self.API_URL = self.apiUrlField.getText()
        # Convert password field to string properly
        apiKeyChars = self.apiKeyField.getPassword()
        self.API_KEY = "".join(apiKeyChars)
        self.MODEL = self.modelField.getText()
        
        try:
            self.MAX_TOKENS = int(self.maxTokensField.getText())
        except:
            self.MAX_TOKENS = self.DEFAULT_MAX_TOKENS

        # Save to Burp settings
        self._callbacks.saveExtensionSetting("apiUrl", self.API_URL)
        self._callbacks.saveExtensionSetting("apiKey", self.API_KEY)
        self._callbacks.saveExtensionSetting("model", self.MODEL)
        self._callbacks.saveExtensionSetting("maxTokens", str(self.MAX_TOKENS))

        dialog.dispose()
        self.statusLabel.setText("Settings saved successfully")
        self.statusLabel.setForeground(Color(100, 200, 100))
        
        print("[+] Settings saved - URL: " + self.API_URL + ", Model: " + self.MODEL)

    def testApiConnection(self, dialog):
        Thread(target=self._testConnection, args=(dialog,)).start()

    def _testConnection(self, dialog):
        try:
            # Get values directly from fields for testing
            testUrl = self.apiUrlField.getText()
            testKey = "".join(self.apiKeyField.getPassword())
            testModel = self.modelField.getText()
            
            print("[DEBUG] Testing connection to: " + testUrl)
            
            test_payload = json.dumps({
                "model": testModel,
                "max_tokens": 50,
                "messages": [
                    {"role": "user", "content": "Say success"}
                ]
            })

            url = URL(testUrl)
            conn = url.openConnection()
            conn.setRequestMethod("POST")
            conn.setRequestProperty("Content-Type", "application/json")
            conn.setRequestProperty("x-api-key", testKey)
            conn.setRequestProperty("anthropic-version", "2023-06-01")
            conn.setDoOutput(True)
            conn.setConnectTimeout(10000)
            conn.setReadTimeout(15000)

            writer = OutputStreamWriter(conn.getOutputStream())
            writer.write(test_payload)
            writer.flush()
            writer.close()

            statusCode = conn.getResponseCode()
            print("[DEBUG] Test connection status: " + str(statusCode))
            
            if statusCode >= 200 and statusCode < 300:
                reader = BufferedReader(InputStreamReader(conn.getInputStream()))
                response = ""
                line = reader.readLine()
                while line is not None:
                    response += line
                    line = reader.readLine()
                reader.close()
                print("[DEBUG] Test response: " + response[:100])
                
                SwingUtilities.invokeLater(lambda: self.statusLabel.setText("Connection test successful!"))
                SwingUtilities.invokeLater(lambda: self.statusLabel.setForeground(Color(100, 200, 100)))
            else:
                SwingUtilities.invokeLater(lambda: self.statusLabel.setText("Connection test failed - HTTP " + str(statusCode)))
                SwingUtilities.invokeLater(lambda: self.statusLabel.setForeground(Color.RED))

            conn.disconnect()
        except Exception as e:
            errorMsg = "Connection test failed: " + str(e)[:60]
            SwingUtilities.invokeLater(lambda: self.statusLabel.setText(errorMsg))
            SwingUtilities.invokeLater(lambda: self.statusLabel.setForeground(Color.RED))
            print("[ERROR] Test connection: " + str(e))

    # ---------- Prompt Editor Dialog ----------
    def showPromptEditor(self, event):
        try:
            dialog = JDialog(SwingUtilities.getWindowAncestor(self.mainPanel), "Edit AI Prompts", True)
            dialog.setLayout(BorderLayout())
            dialog.setSize(700, 500)
            dialog.setLocationRelativeTo(self.mainPanel)

            mainPanel = JPanel(BorderLayout())
            mainPanel.setBackground(self.BG_COLOR)
            mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

            # English prompt
            engLabel = JLabel("English Prompt:")
            engLabel.setForeground(self.TEXT_COLOR)
            engLabel.setFont(self.sansFont)
            self.engPromptArea = JTextArea(8, 60)
            self.engPromptArea.setBackground(self.INPUT_COLOR)
            self.engPromptArea.setForeground(self.TEXT_COLOR)
            self.engPromptArea.setCaretColor(self.TEXT_COLOR)
            self.engPromptArea.setFont(self.monoFont)
            self.engPromptArea.setLineWrap(True)
            self.engPromptArea.setWrapStyleWord(True)
            self.engPromptArea.setText(self.promptEnglish)
            engScroll = JScrollPane(self.engPromptArea)
            engScroll.setBorder(BorderFactory.createLineBorder(self.BORDER_COLOR, 1))

            # Persian prompt
            perLabel = JLabel("Persian (Farsi) Prompt:")
            perLabel.setForeground(self.TEXT_COLOR)
            perLabel.setFont(self.sansFont)
            self.perPromptArea = JTextArea(8, 60)
            self.perPromptArea.setBackground(self.INPUT_COLOR)
            self.perPromptArea.setForeground(self.TEXT_COLOR)
            self.perPromptArea.setCaretColor(self.TEXT_COLOR)
            self.perPromptArea.setFont(self.monoFont)
            self.perPromptArea.setLineWrap(True)
            self.perPromptArea.setWrapStyleWord(True)
            self.perPromptArea.setText(self.promptPersian)
            perScroll = JScrollPane(self.perPromptArea)
            perScroll.setBorder(BorderFactory.createLineBorder(self.BORDER_COLOR, 1))

            noteLabel = JLabel("<html><i>Use {REQUEST} as placeholder for the HTTP request. Prompts are saved automatically.</i></html>")
            noteLabel.setForeground(Color(180, 180, 200))
            noteLabel.setFont(self.sansFont)

            # Layout using GridBag
            centerPanel = JPanel(GridBagLayout())
            centerPanel.setBackground(self.BG_COLOR)
            c = GridBagConstraints()
            c.fill = GridBagConstraints.HORIZONTAL
            c.gridx = 0
            c.weightx = 1.0
            c.insets = Insets(5, 0, 5, 0)

            c.gridy = 0
            centerPanel.add(engLabel, c)
            c.gridy = 1
            c.weighty = 0.3
            c.fill = GridBagConstraints.BOTH
            centerPanel.add(engScroll, c)

            c.gridy = 2
            c.weighty = 0
            c.fill = GridBagConstraints.HORIZONTAL
            centerPanel.add(perLabel, c)
            c.gridy = 3
            c.weighty = 0.3
            c.fill = GridBagConstraints.BOTH
            centerPanel.add(perScroll, c)

            c.gridy = 4
            c.weighty = 0
            c.fill = GridBagConstraints.HORIZONTAL
            centerPanel.add(noteLabel, c)

            mainPanel.add(centerPanel, BorderLayout.CENTER)

            # Buttons
            btnPanel = JPanel(FlowLayout(FlowLayout.RIGHT))
            btnPanel.setBackground(self.BG_COLOR)

            saveBtn = JButton("Save & Close")
            saveBtn.setBackground(self.GREEN_COLOR)
            saveBtn.setForeground(Color.WHITE)
            saveBtn.setFont(self.sansFont.deriveFont(Font.BOLD, 12))
            saveBtn.addActionListener(lambda e: self.savePrompts(dialog))

            cancelBtn = JButton("Cancel")
            cancelBtn.setBackground(Color(100, 100, 110))
            cancelBtn.setForeground(self.TEXT_COLOR)
            cancelBtn.setFont(self.sansFont.deriveFont(Font.BOLD, 12))
            cancelBtn.addActionListener(lambda e: dialog.dispose())

            btnPanel.add(saveBtn)
            btnPanel.add(cancelBtn)
            mainPanel.add(btnPanel, BorderLayout.SOUTH)

            dialog.add(mainPanel)
            dialog.setVisible(True)
        except Exception as e:
            print("[ERROR] showPromptEditor: " + str(e))
            traceback.print_exc()

    def savePrompts(self, dialog):
        self.promptEnglish = self.engPromptArea.getText()
        self.promptPersian = self.perPromptArea.getText()

        self._callbacks.saveExtensionSetting("promptEnglish", self.promptEnglish)
        self._callbacks.saveExtensionSetting("promptPersian", self.promptPersian)

        dialog.dispose()
        self.statusLabel.setText("Prompts saved")
        self.statusLabel.setForeground(Color(100, 200, 100))

    # ---------- Persian toggle ----------
    def onPersianToggle(self, event):
        self.persianMode = self.persianCheckbox.isSelected()
        if self.persianMode:
            self.responseText.setComponentOrientation(ComponentOrientation.RIGHT_TO_LEFT)
            self.responseText.setHorizontalAlignment(JTextArea.RIGHT)
            self.statusLabel.setText("Persian mode: ON")
            self.statusLabel.setForeground(Color(255, 200, 100))
        else:
            self.responseText.setComponentOrientation(ComponentOrientation.LEFT_TO_RIGHT)
            self.responseText.setHorizontalAlignment(JTextArea.LEFT)
            self.statusLabel.setText("Persian mode: OFF")
            self.statusLabel.setForeground(Color(100, 200, 100))

    # ---------- Tab interface ----------
    def getTabCaption(self):
        return "AI Analyzer"

    def getUiComponent(self):
        return self.mainPanel

    # ---------- Context menu ----------
    def createMenuItems(self, invocation):
        self._invocation = invocation
        menuList = []

        menu = JMenu("Send to AI Analyzer")
        menu.setForeground(self.TEXT_COLOR)

        item1 = JMenuItem("Analyze this request")
        item1.setForeground(self.TEXT_COLOR)
        item1.addActionListener(lambda x: self.analyzeFromContext())
        menu.add(item1)

        menu.addSeparator()

        item2 = JMenuItem("Analyze request and response")
        item2.setForeground(self.TEXT_COLOR)
        item2.addActionListener(lambda x: self.analyzeRequestAndResponse())
        menu.add(item2)

        menuList.append(menu)
        return menuList

    def analyzeFromContext(self):
        try:
            if self._invocation:
                messages = self._invocation.getSelectedMessages()
                if messages and len(messages) > 0:
                    request = messages[0].getRequest()
                    requestInfo = self._helpers.analyzeRequest(request)
                    headers = requestInfo.getHeaders()
                    body = request[requestInfo.getBodyOffset():]

                    requestText = "\n".join(headers) + "\n\n" + str(body)
                    self.requestText.setText(requestText)
                    self.requestText.setForeground(self.TEXT_COLOR)
                    self.sendRequest(None)
        except Exception as e:
            print("[ERROR] analyzeFromContext: " + str(e))
            traceback.print_exc()

    def analyzeRequestAndResponse(self):
        try:
            if self._invocation:
                messages = self._invocation.getSelectedMessages()
                if messages and len(messages) > 0:
                    request = messages[0].getRequest()
                    requestInfo = self._helpers.analyzeRequest(request)
                    headers = requestInfo.getHeaders()
                    body = request[requestInfo.getBodyOffset():]

                    requestText = "\n".join(headers) + "\n\n" + str(body)

                    response = messages[0].getResponse()
                    if response:
                        responseInfo = self._helpers.analyzeResponse(response)
                        responseHeaders = responseInfo.getHeaders()
                        responseBody = response[responseInfo.getBodyOffset():]

                        fullText = "=== REQUEST ===\n" + requestText + "\n\n"
                        fullText += "=== RESPONSE ===\n"
                        fullText += "\n".join(responseHeaders) + "\n\n" + str(responseBody)
                    else:
                        fullText = requestText

                    self.requestText.setText(fullText)
                    self.requestText.setForeground(self.TEXT_COLOR)
                    self.sendRequest(None)
        except Exception as e:
            print("[ERROR] analyzeRequestAndResponse: " + str(e))
            traceback.print_exc()

    # ---------- Send request ----------
    def sendRequest(self, event):
        requestText = self.requestText.getText()
        if not requestText or requestText.strip() == "":
            self.statusLabel.setText("ERROR: Request is empty")
            self.statusLabel.setForeground(Color.RED)
            return

        self.sendBtn.setEnabled(False)
        self.sendBtn.setText("Processing...")

        self.statusLabel.setText("Sending to AI...")
        self.statusLabel.setForeground(Color.ORANGE)
        self.responseText.setText("Processing...")
        self.responseText.setForeground(Color.ORANGE)

        Thread(target=self._sendApiRequest, args=(requestText,)).start()

    def clearResponse(self, event):
        self.responseText.setText("Waiting for analysis...")
        self.responseText.setForeground(Color(150, 150, 170))
        self.statusLabel.setText("Cleared")
        self.statusLabel.setForeground(Color(100, 200, 100))
        self.enableSendButton()

    def loadFromProxy(self, event):
        try:
            httpTraffic = self._callbacks.getProxyHistory()
            if httpTraffic and len(httpTraffic) > 0:
                lastItem = httpTraffic[-1]
                request = lastItem.getRequest()
                requestInfo = self._helpers.analyzeRequest(request)
                headers = requestInfo.getHeaders()
                body = request[requestInfo.getBodyOffset():]

                requestText = "\n".join(headers) + "\n\n" + str(body)
                self.requestText.setText(requestText)
                self.requestText.setForeground(self.TEXT_COLOR)
                self.statusLabel.setText("Loaded from Proxy")
                self.statusLabel.setForeground(Color(100, 200, 100))
        except Exception as e:
            self.statusLabel.setText("Error loading: " + str(e))
            self.statusLabel.setForeground(Color.RED)

    def enableSendButton(self):
        try:
            self.sendBtn.setEnabled(True)
            self.sendBtn.setText("Send to AI")
        except:
            pass

    def extractTokenUsage(self, data):
        """Extract token usage from API response"""
        usage_str = ""
        try:
            # Check for usage in the response body
            if "usage" in data:
                usage = data["usage"]
                input_tokens = usage.get("input_tokens", "?")
                output_tokens = usage.get("output_tokens", "?")
                total_tokens = usage.get("total_tokens", "?")
                usage_str = " | Tokens: Input={}, Output={}, Total={}".format(
                    input_tokens, output_tokens, total_tokens
                )
        except:
            pass
        return usage_str

    def _sendApiRequest(self, requestText):
        try:
            # Use the appropriate prompt template
            template = self.promptPersian if self.persianMode else self.promptEnglish
            user_message = template.replace("{REQUEST}", requestText)

            # Prepare the API request payload
            payload = {
                "model": self.MODEL,
                "max_tokens": self.MAX_TOKENS,
                "messages": [
                    {"role": "user", "content": user_message}
                ]
            }

            payload_str = json.dumps(payload)

            print("[DEBUG] Sending request to API...")
            print("[DEBUG] URL: " + self.API_URL)
            print("[DEBUG] Model: " + self.MODEL)
            print("[DEBUG] API Key (first 10 chars): " + self.API_KEY[:10] + "...")
            print("[DEBUG] Payload (truncated): " + payload_str[:200] + "...")

            url = URL(self.API_URL)
            conn = url.openConnection()
            conn.setRequestMethod("POST")
            conn.setRequestProperty("Content-Type", "application/json")
            conn.setRequestProperty("x-api-key", self.API_KEY)
            conn.setRequestProperty("anthropic-version", "2023-06-01")
            conn.setDoOutput(True)
            conn.setConnectTimeout(30000)
            conn.setReadTimeout(120000)

            writer = OutputStreamWriter(conn.getOutputStream())
            writer.write(payload_str)
            writer.flush()
            writer.close()

            statusCode = conn.getResponseCode()
            print("[DEBUG] Response status code: " + str(statusCode))

            if statusCode >= 200 and statusCode < 300:
                reader = BufferedReader(InputStreamReader(conn.getInputStream()))
                response = ""
                line = reader.readLine()
                while line is not None:
                    response += line
                    line = reader.readLine()
                reader.close()

                print("[DEBUG] Response: " + response[:200] + "...")

                try:
                    data = json.loads(response)
                    token_info = self.extractTokenUsage(data)
                    
                    if "content" in data:
                        content_blocks = data["content"]
                        result_text = ""
                        for block in content_blocks:
                            if isinstance(block, dict) and block.get("type") == "text":
                                result_text += block.get("text", "")
                        
                        if result_text:
                            result = result_text
                        else:
                            result = json.dumps(data, indent=2)
                    elif "error" in data:
                        error_info = data["error"]
                        result = "API Error: " + str(error_info.get("message", "Unknown error"))
                    else:
                        result = json.dumps(data, indent=2)
                        
                except Exception as e:
                    result = "Failed to parse JSON response:\n" + response
                    token_info = ""

                # Add token info to result if available
                if token_info:
                    result += "\n\n--- Token Usage ---" + token_info
                
                SwingUtilities.invokeLater(lambda: self._updateUI(result, True, token_info))
            else:
                try:
                    errorReader = BufferedReader(InputStreamReader(conn.getErrorStream()))
                    errorResponse = ""
                    line = errorReader.readLine()
                    while line is not None:
                        errorResponse += line
                        line = errorReader.readLine()
                    errorReader.close()
                except:
                    errorResponse = "Could not read error stream"

                errorMsg = "HTTP Error " + str(statusCode) + "\n\n"
                errorMsg += "Error Body:\n" + errorResponse

                print("[ERROR] " + errorMsg)
                SwingUtilities.invokeLater(lambda: self._updateUI(errorMsg, False, ""))

            conn.disconnect()

        except Exception as e:
            errorMsg = "Exception: " + str(e) + "\n\n"
            errorMsg += traceback.format_exc()
            print("[ERROR] " + errorMsg)
            SwingUtilities.invokeLater(lambda: self._updateUI(errorMsg, False, ""))

    def _updateUI(self, result, success, token_info=""):
        try:
            self.responseText.setText(result)
            self.responseText.setForeground(Color(200, 220, 255))

            if self.persianMode:
                self.responseText.setComponentOrientation(ComponentOrientation.RIGHT_TO_LEFT)
                self.responseText.setHorizontalAlignment(JTextArea.RIGHT)
            else:
                self.responseText.setComponentOrientation(ComponentOrientation.LEFT_TO_RIGHT)
                self.responseText.setHorizontalAlignment(JTextArea.LEFT)

            if success:
                statusMsg = "Analysis completed successfully"
                if token_info:
                    statusMsg += token_info
                self.statusLabel.setText(statusMsg)
                self.statusLabel.setForeground(Color(100, 200, 100))
            else:
                self.statusLabel.setText("Analysis failed - see response for details")
                self.statusLabel.setForeground(Color.RED)
        finally:
            self.enableSendButton()
