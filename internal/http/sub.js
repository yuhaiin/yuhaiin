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

function update() {
    var links = selectSubs();

    window.location = "/sub/update?links=" + encodeURIComponent(links);
}

function delSubs() {
    var links = selectSubs();


    if (confirm("Are you sure to delete these subs?\n" + links)) {
        window.location = "/sub/delete?links=" + encodeURIComponent(links);
    }
}

function selectSubs() {
    //飞鸟慕鱼博客
    //获取所有的 checkbox 属性的 input标签
    obj = document.getElementsByName("links");
    check_val = [];
    for (k in obj) {
        //判断复选框是否被选中
        if (obj[k].checked)
            //获取被选中的复选框的值
            check_val.push(obj[k].value);
    }

    return JSON.stringify(check_val);
}