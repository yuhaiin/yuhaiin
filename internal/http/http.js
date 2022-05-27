const mobileAdapter = () => {
    let WIDTH = screen.width
    let content = `width=${WIDTH}, initial-scale=1, maximum-scale=1, minimum-scale=1`
    let meta = document.querySelector('meta[name=viewport]')
    if (!meta) {
        meta = document.createElement('meta')
        meta.setAttribute('name', 'viewport')
        document.head.appendChild(meta)
    }
    meta.setAttribute('content', content)
}
mobileAdapter()
window.onorientationchange = mobileAdapter //屏幕翻转时再次执行