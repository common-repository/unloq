<?php
$unloq_script = '<script type="text/javascript" src="https://plugin.unloq.io/login.js" data-unloq-theme="light" data-unloq-key="' . $unloq_widget_key . '"></script>';
?>
<?php
// Login with UNLOQ only
if($unloq_type == "UNLOQ") { ?>
    <div class="unloq-login-box">
        <?php echo $unloq_script; ?>
        <script type="text/javascript">
            (function() {
                if(typeof window.UNLOQ !== 'object' || !window.UNLOQ || typeof window.UNLOQ.onLogin !== 'function') return;
                window.UNLOQ.onLogin(function(data) {
                    if(typeof data !== 'object' || !data) return;
                    if(typeof data.token !== 'string' || !data.token) return;
                    var redirUrl = window.location.href.split('#')[0];
                    redirUrl += (redirUrl.indexOf('?') === -1 ? '?' : '&');
                    redirUrl += 'unloq_uauth=login&token=' + data.token;
                    try {
                      window.location.replace(redirUrl);
                    } catch(e) {
                      window.location.href = redirUrl;
                    }
                });
            })();
        </script>
    </div>
<?php } else { ?>
    <div id="btnInitUnloq" class="unloq-init" data-script="https://plugin.unloq.io/login.js" data-theme="light" data-key="<?php echo $unloq_widget_key; ?>"></div>
<?php } ?>
