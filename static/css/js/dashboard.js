document.addEventListener("DOMContentLoaded", function () {

    const rows = document.querySelectorAll(".event-row");

    rows.forEach(function (row) {

        row.addEventListener("click", function () {

            alert("Event clicked!");

        });

    });

});