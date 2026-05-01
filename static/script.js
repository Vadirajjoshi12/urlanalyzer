function typeText(element, text, speed = 20) {
    let i = 0;
    element.innerHTML = "";

    function type() {
        if (i < text.length) {
            element.innerHTML += text.charAt(i);
            i++;
            setTimeout(type, speed);
        }
    }

    type();
}

async function analyze() {

    let urlInput = document.getElementById("urlInput");
    let url = urlInput.value.trim();

    if (!url) {
        alert("Please enter a URL first!");
        return;
    }

    const loader = document.getElementById("loader");
    const result = document.getElementById("result");
    const loadingText = document.getElementById("loadingText");

    // 🔄 Show shimmer loader
    loader.classList.remove("hidden");
    result.innerHTML = "";

    // 🔄 Loading messages
    let messages = [
        "🔍 Scanning URL...",
        "🔗 Checking links...",
        "🧠 Analyzing behavior...",
        "🤖 Fetching AI Insight..."
    ];

    let i = 0;
    let textInterval = setInterval(() => {
        loadingText.innerText = messages[i % messages.length];
        i++;
    }, 800);

    try {
        let res = await fetch("/analyze", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url: url })
        });

        if (!res.ok) {
            throw new Error("Server error - check Flask.");
        }

        let data = await res.json();

        clearInterval(textInterval);
        loader.classList.add("hidden");

        if (data.error) {
            result.innerHTML = `
                <div class="result-card">
                    <p style="color:red;">Error: ${data.error}</p>
                </div>`;
            return;
        }

        // 🎨 STATUS
        let statusClass = data.status.toLowerCase();
        let barColor = data.status === "Safe" ? "#2ecc71"
                    : data.status === "Suspicious" ? "#f39c12"
                    : "#e74c3c";

        // 📌 Reasons
        let reasonsHTML = (data.reasons || [])
            .map(r => `<li>${r}</li>`)
            .join("");

        if (!reasonsHTML) {
            reasonsHTML = "<li>No specific threats detected.</li>";
        }

        // 🤖 AI Box
        let aiHTML = "";
        if (data.ai_summary) {
            aiHTML = `
                <hr>
                <div class="ai-box">
                    <h3>🔍 AI Insight</h3>
                    <div id="ai-text" class="ai-typing"></div>
                </div>
            `;
        }

        // 🧾 Render Result
        result.innerHTML = `
            <div class="result-card">
                <h2 class="${statusClass}">${data.status}</h2>

                <p><b>Risk Score:</b> ${data.score}/100</p>

                <div class="bar">
                    <div class="fill" style="width:${data.score}%; background:${barColor};"></div>
                </div>

                <ul class="reasons">${reasonsHTML}</ul>

                ${aiHTML}
            </div>
        `;

        // 🔥 Typing AI
        if (data.ai_summary) {
            let aiText = document.getElementById("ai-text");

            let cleanText = data.ai_summary
                .replace(/\*\*/g, "")
                .replace(/\* /g, "• ")
                .replace(/- /g, "• ");

            typeText(aiText, cleanText, 15);
        }

    } catch (err) {

        clearInterval(textInterval);
        loader.classList.add("hidden");

        result.innerHTML = `
            <div class="result-card">
                <h2 class="dangerous">Error</h2>
                <p>${err.message}</p>
            </div>
        `;
    }
}