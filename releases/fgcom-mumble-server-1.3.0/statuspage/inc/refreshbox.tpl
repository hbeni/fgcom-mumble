<form> 
    <select id="s_refresh" onchange="setCookie('refresh', this.options[this.selectedIndex].value); window.setTimeout(function(){ document.location.reload(true); }, this.options[this.selectedIndex].value*1000);">
        <option value="0" selected>no refresh</option>
        <!--<option value="5">5 secs</option>-->
        <option value="10">10 secs</option>
        <option value="15">15 secs</option>
        <option value="30">30 secs</option>
        <option value="60">60 secs</option>
        <option value="90">90 secs</option>
        <option value="120">2 min</option>
        <option value="300">5 min</option>
        <option value="600">10 min</option>
        <option value="900">15 min</option>
        <option value="1800">30 min</option>
        <option value="3600">1 hr</option>
    </select> 
</form>
<script>
    var refresh  = ( getCookie('refresh' ) ? getCookie('refresh' ) : 0 );
    if (refresh > 0) {
        window.setTimeout(function(){ document.location.reload(true); }, refresh*1000);
        let element = document.getElementById('s_refresh').value = refresh;
    }
</script> 
