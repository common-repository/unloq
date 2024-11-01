/*
 * Included when the site uses both UNLOQ and password login. This is used to perform the toggle.
 * */
(function() {
  var JQUERY_INTEGRITY = 'sha256-ZosEbRLbNQzLpnKIkEdrPv7lOy9C27hHQ+Xp8a4MxAQ=';
  var JQUERY_URL = "https://code.jquery.com/jquery-1.12.4.min.js";

  if (typeof window.jQuery === 'object' && window.jQuery && typeof window.jQuery.noConflict === 'function') {
    loadPlugin(window.jQuery.noConflict());
  } else {
    var script = document.createElement('script');
    script.onload = function() {
      loadPlugin(jQuery.noConflict());
    };
    script.onerror = function() {
      console.log("Could not load jQuery dependency");
    };
    script.integrity = JQUERY_INTEGRITY;
    try {
      script.setAttribute('integrity', JQUERY_INTEGRITY);
    } catch (e) {
    }
    script.crossorigin = "anonymous";
    try {
      script.setAttribute('crossorigin', 'anonymous');
    } catch (e) {
    }
    script.src = JQUERY_URL;
    document.getElementsByTagName('head')[0].appendChild(script);
  }

  function loadPlugin($) {
    var $btn = $("#btnInitUnloq");
    if (!$btn || $btn.size() === 0) return;  // unloq-only.
    var $login = $("#login"),
      $form = $login.find("form").first();
    if ($login.size() === 0) {
      // something went wrong.
      console.error('UNLOQ Failed to initialize, the login form was no-where to be found.');
      return;
    }
    var PLUGIN_URL = $btn.attr("data-script"),
      PLUGIN_THEME = $btn.attr("data-theme"),
      PLUGIN_KEY = $btn.attr("data-key");
    $btn.remove();
    $form.wrap("<div class='tabs'></div>");
    var $tabs = $form.parent();
    $tabs.prepend('<div class="unloq-login-box"></div>');
    $tabs.prepend("<div class='tab tab-unloq'><span>UNLOQ</span></div>");
    $tabs.prepend("<div class='tab tab-login'><span>Password login</span></div>");
    $tabs.prepend("<div class='tab-line'></div>");

    var $unloqBox = $tabs.children(".unloq-login-box"),
      isInitialized = false;

    /* initializez the unloq plugin. */
    function initialize() {
      var $scr = $("<script></script>");
      $scr.attr("type", "text/javascript");
      $scr.attr("data-unloq-key", PLUGIN_KEY);
      $scr.attr("data-unloq-theme", PLUGIN_THEME);
      $unloqBox.append($scr);
      $scr.attr("src", PLUGIN_URL);
      isInitialized = true;
      $scr.load(function() {
        if (typeof window.UNLOQ !== 'object' || !window.UNLOQ) return;
        if (typeof window.UNLOQ.onLogin !== 'function') return;
        // Manually handle the redirect, to avoid issues with token and redirect loops.
        window.UNLOQ.onLogin(function(data) {
          if (typeof data !== 'object' || !data) return;
          if (typeof data.token !== 'string' || !data.token) return;
          var redirUrl = window.location.href.split('#')[0];
          redirUrl += (redirUrl.indexOf('?') === -1 ? '?' : '&');
          redirUrl += 'unloq_uauth=login&token=' + data.token;
          try {
            window.location.replace(redirUrl);
          } catch(e) {
            window.location.href = redirUrl;
          }
        });
      });
    }

    function onChange() {
      var which = ($(this).hasClass('tab-unloq') ? 'unloq' : 'password'),
        $parent = $(this).parent();
      if (which == 'unloq') {
        if ($parent.hasClass('password-active')) {
          $parent.removeClass('password-active');
        }
        if ($parent.hasClass('unloq-active')) return;
        $parent.addClass('unloq-active');
        if (isInitialized) return;
        initialize();
      } else {
        if ($parent.hasClass('unloq-active')) {
          $parent.removeClass('unloq-active');
        }
        if ($parent.hasClass('password-active')) return;
        $parent.addClass('password-active');
      }
    }

    $tabs.on('click touchstart', '> .tab', onChange);
    if ($tabs.hasClass('unloq-active')) {
      initialize();
    }
  }
})();
