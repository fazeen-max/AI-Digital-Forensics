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

            panel.innerHTML = `
                <div class="investigation-details">

                    <h3>Event Investigation</h3>

                    <p><strong>Time:</strong> ${time}</p>

                    <p><strong>User:</strong> ${username}</p>

                    <p><strong>Source IP:</strong> ${sourceIP}</p>

                    <p><strong>Event:</strong> ${eventType}</p>

                    <p><strong>Threat:</strong> ${threat}</p>

                    <p><strong>AI Confidence:</strong> ${confidence}</p>

                </div>
            `;

            rows.forEach(function (item) {
                item.classList.remove("selected-event");
            });

            row.classList.add("selected-event");
        });

    });

});