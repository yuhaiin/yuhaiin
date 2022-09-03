function add() {
    let name = document.getElementById("name").value;
    let link = document.getElementById("link").value;

    var xmlhttp = new XMLHttpRequest();
    xmlhttp.open("POST", "/sub?name=" + encodeURIComponent(name) + "&link=" + encodeURIComponent(link), true);
    xmlhttp.onreadystatechange = function () {
        if (xmlhttp.readyState != 4) return;
        if (xmlhttp.status == 200) window.location = "/sub";
    }
    xmlhttp.send();
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

function update() {
    const ub = document.querySelector('#update_button');
    ub.innerText = "UPDATING...";

    var links = selectSubs();
    var xmlhttp = new XMLHttpRequest();
    xmlhttp.open("PATCH", "/sub?links=" + encodeURIComponent(links), true);
    xmlhttp.onreadystatechange = function () {
        if (xmlhttp.readyState != 4) return;
        ub.innerText = "UPDATE";
        window.location = "/sub";
    }
    xmlhttp.send();
}

function delSubs() {
    var links = selectSubs();
    if (confirm("Are you sure to delete these subs?\n" + links)) {
        var xmlhttp = new XMLHttpRequest();
        xmlhttp.open("DELETE", "/sub?links=" + encodeURIComponent(links), true);
        xmlhttp.onreadystatechange = function () {
            if (xmlhttp.readyState != 4) return;
            if (xmlhttp.status == 200) window.location = "/sub";
        }
        xmlhttp.send();
    }
}

function selectSubs() {
    check_val = [];
    document.querySelectorAll('input[name=links]:checked').forEach((v) => { check_val.push(v.value) })
    return JSON.stringify(check_val);
}

function linkSelectOrCopy(name, link) {
    const i = document.querySelector('input[name=links][value="' + name + '"]')
    if (i.checked === true) {
        copy(link)
        i.checked = false
    }
    else i.checked = true
}