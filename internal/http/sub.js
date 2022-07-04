function add() {
    let name = document.getElementById("name").value;
    let link = document.getElementById("link").value;

    const re = "/sub/add?name=" + encodeURIComponent(name) + "&link=" + encodeURIComponent(link);
    console.log(re);
    window.location = re;
}

function copy(link) {
    navigator.clipboard.writeText(link).then(function () {
        show_toast("Copy Successful");
        console.log("Copied to clipboard");
    }, function (err) {
        show_toast("Copy Failed: " + err);
        console.error("Could not copy to clipboard", err);
    });
}