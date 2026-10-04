
</head>
<body>

<img class="logo" src="https://files.catbox.moe/cm4183.jpg" alt="BetterHax logo">

<h1>BetterHax (1.26.50)</h1>

<blockquote>
  <p><strong>Notice:</strong> BetterHax is a modified fork of
  <a href="https://github.com/hax0r31337/ProtoHax-Android">ProtoHax-Android</a>,
  updated to support the latest Minecraft: Bedrock Edition version
  (<strong>1.26.50</strong>). The original ProtoHax was made by
  <strong>hax0r31337</strong> and is now developed as a closed-source project at
  <strong><a href="https://protohax.net">protohax.net</a></strong>.
  BetterHax is maintained independently by <strong>me</strong> and is
  <strong>not affiliated with or endorsed by</strong> the original author.</p>
</blockquote>

<p>ProtoHax-Android is the Android implementation of
<a href="https://github.com/hax0r31337/ProtoHax">ProtoHax</a>, an open-source cheat for
Minecraft: Bedrock Edition that works through the network layer. BetterHax continues that
approach, bringing the Android client forward to current protocol versions.</p>

<h2>What's Different in BetterHax?</h2>
<ul>
  <li><strong>Updated to Minecraft 1.26.50</strong> (protocol version 2193)</li>
  <li>Updated <strong>CloudburstMC Protocol</strong> dependency to the latest version</li>
  <li>Implemented <strong>dynamic codec selection</strong> (<code>RelayListenerAutoCodec</code>)
      so the relay adapts to the client's protocol version instead of hardcoding one</li>
  <li>Refreshed packet structures used by modules (combat, movement, visual, misc)</li>
  <li>Rewrote the <strong>VPN backend in pure Java</strong> (the original was closed-source)</li>
  <li>General build modernization (Gradle, AGP, target SDK)</li>
</ul>
<p>Everything else — the module framework, event system, and overall architecture — is
inherited from ProtoHax and remains under the same license.</p>

<h2>Features</h2>
<ol>
  <li>No modifications to the Minecraft client</li>
  <li>Seamless switching/adapting across multiple versions</li>
  <li>Full control of the packet layer</li>
</ol>

<h2>Issues</h2>
<ul>
  <li>For bugs or missing features <strong>specific to BetterHax</strong>, open an issue on this repository.</li>
  <li>For issues with the <strong>original ProtoHax cheat logic</strong>, refer to the upstream
      repository <a href="https://github.com/hax0r31337/ProtoHax/issues">here</a> — though note it
      is no longer actively maintained.</li>
</ul>
<p>This is an <strong>English-only</strong> repository. All issues and pull requests must be in
English. If you can't speak English, please use a
<a href="https://translate.google.com/">translator</a>.</p>

<h2>License</h2>
<p>This project is subject to the
<a href="https://www.gnu.org/licenses/gpl-3.0.en.html">GNU General Public License v3.0</a>,
inherited from ProtoHax. This applies only to source code located directly in this repository.
During development and compilation, additional source code may be used to which no rights have
been obtained. Such code is not covered by the GPL license.</p>

<p>For those unfamiliar with the license, here is a summary of its main points. This is by no
means legal advice nor legally binding.</p>

<p><em>Actions that you are allowed to do:</em></p>
<ul>
  <li>Use</li>
  <li>Share</li>
  <li>Modify</li>
</ul>

<p><em>If you do decide to use ANY code from the source:</em></p>
<ul>
  <li><strong>You must disclose the source code of your modified work and the source code you took
      from this project. This means you are not allowed to use code from this project (even
      partially) in a closed-source (or even obfuscated) application.</strong></li>
  <li><strong>Your modified application must also be licensed under the GPL.</strong></li>
</ul>

<h2>Credits</h2>
<ul>
  <li><strong>hax0r31337</strong> — original creator of ProtoHax and ProtoHax-Android</li>
  <li><strong>BetterHax contributors</strong> — updates for 1.26.50, VPN rewrite, and ongoing maintenance</li>
</ul>

<h2>Installation</h2>
<p>BetterHax uses the
<a href="https://docs.gradle.org/current/userguide/declaring_repositories.html#sec:case-for-maven-local">local maven repository</a>.
You need to build and publish the core
<a href="https://github.com/hax0r31337/ProtoHax">ProtoHax</a> library to the local repository
before you can build, sorry for the inconvenience.</p>

<h3>With Android Studio</h3>
<ol>
  <li>Clone the repository: <code>git clone https://github.com/&lt;your-username&gt;/BetterHax.git</code></li>
  <li>Import the project into Android Studio</li>
  <li>Connect your Android device to your computer</li>
  <li>Build and run the project on your device</li>
</ol>

<h3>With Gradle</h3>
<ol>
  <li>Clone the repository: <code>git clone https://github.com/&lt;your-username&gt;/BetterHax.git</code></li>
  <li>CD into the local repository</li>
  <li>Connect your Android device to your computer</li>
  <li>Run <code>gradlew app:assembleDebug</code></li>
</ol>

<h2>Contributing</h2>
<p>Contributions are welcome! If you'd like to help, please fork the repository and make changes
as you'd like. Pull requests are welcome.</p>

<h2>Disclaimer</h2>
<p>Please use BetterHax at your own risk. <strong>We DO NOT take responsibility for any bans or
punishments that may occur as a result of using this cheat.</strong> BetterHax is not affiliated
with the original ProtoHax author, Mojang, or Microsoft.</p>

</body>
</html>
