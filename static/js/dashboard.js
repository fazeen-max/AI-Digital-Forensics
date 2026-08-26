document.addEventListener("DOMContentLoaded", function () {

    const rows = document.querySelectorAll(".event-row");
    const panel = document.querySelector(".investigation-content");

    rows.forEach(function (row) {

        row.addEventListener("click", function () {

            const cells = row.querySelectorAll("td");

            const time = cells[0].textContent.trim();
            const username = cells[1].textContent.trim();
            const sourceIP = cells[2].textContent.trim();
            const eventType = cells[3].textContent.trim();
            const threat = cells[4].textContent.trim();
            const confidence = cells[5].textContent.trim();
            const forensicReason = cells[6].textContent.trim();

            panel.innerHTML = `
                <div class="investigation-details">

                    <h3>Event Investigation</h3>

                    <p><strong>Time:</strong> ${time}</p>
                    <p><strong>User:</strong> ${username}</p>
                    <p><strong>Source IP:</strong> ${sourceIP}</p>
                    <p><strong>Event:</strong> ${eventType}</p>
                    <p><strong>Threat:</strong> ${threat}</p>
                    <p><strong>AI Confidence:</strong> ${confidence}</p>
                    <p><strong>Forensic Reason:</strong> ${forensicReason}</p>

                </div>
            `;

            rows.forEach(function (item) {
                item.classList.remove("selected-event");
            });

            row.classList.add("selected-event");

        });

    });

    const normalCount = Number(
        document.body.dataset.normal
    );

    const suspiciousCount = Number(
        document.body.dataset.suspicious
    );

    const maliciousCount = Number(
        document.body.dataset.malicious
    );

    const totalEvents =
        normalCount +
        suspiciousCount +
        maliciousCount;

    if (totalEvents > 0) {

        const normalMeter =
            document.querySelector(".meter-normal");

        const suspiciousMeter =
            document.querySelector(".meter-suspicious");

        const maliciousMeter =
            document.querySelector(".meter-malicious");

        if (normalMeter) {
            normalMeter.style.width =
                (normalCount / totalEvents * 100) + "%";
        }

        if (suspiciousMeter) {
            suspiciousMeter.style.width =
                (suspiciousCount / totalEvents * 100) + "%";
        }

        if (maliciousMeter) {
            maliciousMeter.style.width =
                (maliciousCount / totalEvents * 100) + "%";
        }

    }

});