
/* ---- Class.coffee ---- */


(function() {
  var Class,
    slice = [].slice;

  Class = (function() {
    function Class() {}

    Class.prototype.trace = true;

    Class.prototype.log = function() {
      var args;
      args = 1 <= arguments.length ? slice.call(arguments, 0) : [];
      if (!this.trace) {
        return;
      }
      if (typeof console === 'undefined') {
        return;
      }
      args.unshift("[" + this.constructor.name + "]");
      console.log.apply(console, args);
      return this;
    };

    Class.prototype.logStart = function() {
      var args, name;
      name = arguments[0], args = 2 <= arguments.length ? slice.call(arguments, 1) : [];
      if (!this.trace) {
        return;
      }
      this.logtimers || (this.logtimers = {});
      this.logtimers[name] = +(new Date);
      if (args.length > 0) {
        this.log.apply(this, ["" + name].concat(slice.call(args), ["(started)"]));
      }
      return this;
    };

    Class.prototype.logEnd = function() {
      var args, ms, name;
      name = arguments[0], args = 2 <= arguments.length ? slice.call(arguments, 1) : [];
      ms = +(new Date) - this.logtimers[name];
      this.log.apply(this, ["" + name].concat(slice.call(args), ["(Done in " + ms + "ms)"]));
      return this;
    };

    return Class;

  })();

  window.Class = Class;

}).call(this);

/* ---- Console.coffee ---- */


(function() {
  var Console,
    bind = function(fn, me){ return function(){ return fn.apply(me, arguments); }; },
    extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  Console = (function(superClass) {
    extend(Console, superClass);

    function Console(sidebar) {
      var handleMessageWebsocket_original;
      this.sidebar = sidebar;
      this.handleTabClick = bind(this.handleTabClick, this);
      this.changeFilter = bind(this.changeFilter, this);
      this.stopDragY = bind(this.stopDragY, this);
      this.cleanup = bind(this.cleanup, this);
      this.onClosed = bind(this.onClosed, this);
      this.onOpened = bind(this.onOpened, this);
      this.open = bind(this.open, this);
      this.close = bind(this.close, this);
      this.loadConsoleText = bind(this.loadConsoleText, this);
      this.addLines = bind(this.addLines, this);
      this.formatLine = bind(this.formatLine, this);
      this.checkTextIsBottom = bind(this.checkTextIsBottom, this);
      this.tag = null;
      this.opened = false;
      this.filter = null;
      this.tab_types = [
        {
          title: "All",
          filter: ""
        }, {
          title: "Info",
          filter: "INFO"
        }, {
          title: "Warning",
          filter: "WARNING"
        }, {
          title: "Error",
          filter: "ERROR"
        }
      ];
      this.read_size = 32 * 1024;
      this.tab_active = "";
      handleMessageWebsocket_original = this.sidebar.wrapper.handleMessageWebsocket;
      this.sidebar.wrapper.handleMessageWebsocket = (function(_this) {
        return function(message) {
          if (message.cmd === "logLineAdd" && message.params.stream_id === _this.stream_id) {
            return _this.addLines(message.params.lines);
          } else {
            return handleMessageWebsocket_original(message);
          }
        };
      })(this);
      $(window).on("hashchange", (function(_this) {
        return function() {
          if (window.top.location.hash.startsWith("#EpixNet:Console")) {
            return _this.open();
          }
        };
      })(this));
      if (window.top.location.hash.startsWith("#EpixNet:Console")) {
        setTimeout(((function(_this) {
          return function() {
            return _this.open();
          };
        })(this)), 10);
      }
    }

    Console.prototype.createHtmltag = function() {
      var j, len, ref, tab, tab_type;
      if (!this.container) {
        this.container = $("<div class=\"console-container\">\n	<div class=\"console\">\n		<div class=\"console-top\">\n			<div class=\"console-tabs\"></div>\n			<div class=\"console-text\">Loading...</div>\n		</div>\n		<div class=\"console-middle\">\n			<div class=\"mynode\"></div>\n			<div class=\"peers\">\n				<div class=\"peer\"><div class=\"line\"></div><a href=\"#\" class=\"icon\">\u25BD</div></div>\n			</div>\n		</div>\n	</div>\n</div>");
        this.text = this.container.find(".console-text");
        this.text_elem = this.text[0];
        this.tabs = this.container.find(".console-tabs");
        this.text.on("mousewheel", (function(_this) {
          return function(e) {
            if (e.originalEvent.deltaY < 0) {
              _this.text.stop();
            }
            return RateLimit(300, _this.checkTextIsBottom);
          };
        })(this));
        this.text.is_bottom = true;
        this.container.appendTo(this.sidebar.wrapper.chrome.element);
        this.tag = this.container.find(".console");
        ref = this.tab_types;
        for (j = 0, len = ref.length; j < len; j++) {
          tab_type = ref[j];
          tab = $("<a></a>", {
            href: "#",
            "data-filter": tab_type.filter,
            "data-title": tab_type.title
          }).text(tab_type.title);
          if (tab_type.filter === this.tab_active) {
            tab.addClass("active");
          }
          tab.on("click", this.handleTabClick);
          if (window.top.location.hash.endsWith(tab_type.title)) {
            this.log("Triggering click on", tab);
            tab.trigger("click");
          }
          this.tabs.append(tab);
        }
        this.container.on("mousedown touchend touchcancel", (function(_this) {
          return function(e) {
            if (e.target !== e.currentTarget) {
              return true;
            }
            _this.log("closing");
            if ($(document.body).hasClass("body-console")) {
              _this.close();
              return true;
            }
          };
        })(this));
        return this.loadConsoleText();
      }
    };

    Console.prototype.checkTextIsBottom = function() {
      return this.text.is_bottom = Math.round(this.text_elem.scrollTop + this.text_elem.clientHeight) >= this.text_elem.scrollHeight - 15;
    };

    Console.prototype.toColor = function(text, saturation, lightness) {
      var hash, i, j, ref;
      if (saturation == null) {
        saturation = 60;
      }
      if (lightness == null) {
        lightness = 70;
      }
      hash = 0;
      for (i = j = 0, ref = text.length - 1; 0 <= ref ? j <= ref : j >= ref; i = 0 <= ref ? ++j : --j) {
        hash += text.charCodeAt(i) * i;
        hash = hash % 1777;
      }
      return "hsl(" + (hash % 360) + ("," + saturation + "%," + lightness + "%)");
    };

    Console.prototype.formatLine = function(line) {
      var added, level, match, module, ref, text;
      match = line.match(/(\[.*?\])[ ]+(.*?)[ ]+(.*?)[ ]+(.*)/);
      if (!match) {
        return line.replace(/\</g, "&lt;").replace(/\>/g, "&gt;");
      }
      ref = line.match(/(\[.*?\])[ ]+(.*?)[ ]+(.*?)[ ]+(.*)/), line = ref[0], added = ref[1], level = ref[2], module = ref[3], text = ref[4];
      added = "<span style='color: #dfd0fa'>" + added + "</span>";
      level = "<span style='color: " + (this.toColor(level, 100)) + ";'>" + level + "</span>";
      module = "<span style='color: " + (this.toColor(module, 60)) + "; font-weight: bold;'>" + module + "</span>";
      text = text.replace(/(Xite:[A-Za-z0-9\.]+)/g, "<span style='color: #AAAAFF'>$1</span>");
      text = text.replace(/\</g, "&lt;").replace(/\>/g, "&gt;");
      return added + " " + level + " " + module + " " + text;
    };

    Console.prototype.addLines = function(lines, animate) {
      var html_lines, j, len, line;
      if (animate == null) {
        animate = true;
      }
      html_lines = [];
      this.logStart("formatting");
      for (j = 0, len = lines.length; j < len; j++) {
        line = lines[j];
        html_lines.push(this.formatLine(line));
      }
      this.logEnd("formatting");
      this.logStart("adding");
      this.text.append(html_lines.join("<br>") + "<br>");
      this.logEnd("adding");
      if (this.text.is_bottom && animate) {
        return this.text.stop().animate({
          scrollTop: this.text_elem.scrollHeight - this.text_elem.clientHeight + 1
        }, 600, 'easeInOutCubic');
      }
    };

    Console.prototype.loadConsoleText = function() {
      this.sidebar.wrapper.ws.cmd("consoleLogRead", {
        filter: this.filter,
        read_size: this.read_size
      }, (function(_this) {
        return function(res) {
          var pos_diff, size_read, size_total;
          _this.text.html("");
          pos_diff = res["pos_end"] - res["pos_start"];
          size_read = Math.round(pos_diff / 1024);
          size_total = Math.round(res['pos_end'] / 1024);
          _this.text.append("<br><br>");
          _this.text.append("Displaying " + res.lines.length + " of " + res.num_found + " lines found in the last " + size_read + "kB of the log file. (" + size_total + "kB total)<br>");
          _this.addLines(res.lines, false);
          return _this.text_elem.scrollTop = _this.text_elem.scrollHeight;
        };
      })(this));
      if (this.stream_id) {
        this.sidebar.wrapper.ws.cmd("consoleLogStreamRemove", {
          stream_id: this.stream_id
        });
      }
      return this.sidebar.wrapper.ws.cmd("consoleLogStream", {
        filter: this.filter
      }, (function(_this) {
        return function(res) {
          return _this.stream_id = res.stream_id;
        };
      })(this));
    };

    Console.prototype.close = function() {
      window.top.location.hash = "";
      this.sidebar.move_lock = "y";
      this.sidebar.startDrag();
      return this.sidebar.stopDrag();
    };

    Console.prototype.open = function() {
      this.sidebar.startDrag();
      this.sidebar.moved("y");
      this.sidebar.fixbutton_targety = this.sidebar.page_height - this.sidebar.fixbutton_inity - 50;
      return this.sidebar.stopDrag();
    };

    Console.prototype.onOpened = function() {
      this.sidebar.onClosed();
      return this.log("onOpened");
    };

    Console.prototype.onClosed = function() {
      $(document.body).removeClass("body-console");
      if (this.stream_id) {
        return this.sidebar.wrapper.ws.cmd("consoleLogStreamRemove", {
          stream_id: this.stream_id
        });
      }
    };

    Console.prototype.cleanup = function() {
      if (this.container) {
        this.container.remove();
        return this.container = null;
      }
    };

    Console.prototype.stopDragY = function() {
      var targety;
      if (this.sidebar.fixbutton_targety === this.sidebar.fixbutton_inity) {
        targety = 0;
        this.opened = false;
      } else {
        targety = this.sidebar.fixbutton_targety - this.sidebar.fixbutton_inity;
        this.onOpened();
        this.opened = true;
      }
      if (this.tag) {
        this.tag.css("transition", "0.5s ease-out");
        this.tag.css("transform", "translateY(" + targety + "px)").one(transitionEnd, (function(_this) {
          return function() {
            _this.tag.css("transition", "");
            if (!_this.opened) {
              return _this.cleanup();
            }
          };
        })(this));
      }
      this.log("stopDragY", "opened:", this.opened, targety);
      if (!this.opened) {
        return this.onClosed();
      }
    };

    Console.prototype.changeFilter = function(filter) {
      this.filter = filter;
      if (this.filter === "") {
        this.read_size = 32 * 1024;
      } else {
        this.read_size = 5 * 1024 * 1024;
      }
      return this.loadConsoleText();
    };

    Console.prototype.handleTabClick = function(e) {
      var elem;
      elem = $(e.currentTarget);
      this.tab_active = elem.data("filter");
      $("a", this.tabs).removeClass("active");
      elem.addClass("active");
      this.changeFilter(this.tab_active);
      window.top.location.hash = "#EpixNet:Console:" + elem.data("title");
      return false;
    };

    return Console;

  })(Class);

  window.Console = Console;

}).call(this);

/* ---- Menu.coffee ---- */


(function() {
  var Menu,
    slice = [].slice;

  Menu = (function() {
    function Menu(button, chrome) {
      this.button = button;
      this.chrome = chrome;
      this.elem = $(".menu.template").clone().removeClass("template");
      this.elem.appendTo(this.chrome.element);
      this.items = [];
    }

    Menu.prototype.show = function() {
      var button_pos, left;
      if (window.visible_menu && window.visible_menu.button[0] === this.button[0]) {
        window.visible_menu.hide();
        return this.hide();
      } else {
        button_pos = this.chrome.position(this.button[0]);
        left = button_pos.left;
        this.elem.css({
          "top": button_pos.top + this.button.outerHeight(),
          "left": left
        });
        this.button.addClass("menu-active");
        this.elem.addClass("visible");
        if (this.chrome.position(this.elem[0]).left + this.elem.width() + 20 > this.chrome.width) {
          this.elem.css("left", this.chrome.width - this.elem.width() - 20);
        }
        if (window.visible_menu) {
          window.visible_menu.hide();
        }
        return window.visible_menu = this;
      }
    };

    Menu.prototype.hide = function() {
      this.elem.removeClass("visible");
      this.button.removeClass("menu-active");
      return window.visible_menu = null;
    };

    Menu.prototype.addItem = function(title, cb) {
      var item;
      item = $(".menu-item.template", this.elem).clone().removeClass("template");
      item.html(title);
      item.on("click", (function(_this) {
        return function() {
          if (!cb(item)) {
            _this.hide();
          }
          return false;
        };
      })(this));
      item.appendTo(this.elem);
      this.items.push(item);
      return item;
    };

    Menu.prototype.log = function() {
      var args;
      args = 1 <= arguments.length ? slice.call(arguments, 0) : [];
      return console.log.apply(console, ["[Menu]"].concat(slice.call(args)));
    };

    return Menu;

  })();

  window.Menu = Menu;

  $("body").on("click", function(e) {
    if (window.visible_menu && e.target !== window.visible_menu.button[0] && $(e.target).parent()[0] !== window.visible_menu.elem[0]) {
      return window.visible_menu.hide();
    }
  });

}).call(this);

/* ---- Prototypes.coffee ---- */


(function() {
  String.prototype.startsWith = function(s) {
    return this.slice(0, s.length) === s;
  };

  String.prototype.endsWith = function(s) {
    return s === '' || this.slice(-s.length) === s;
  };

  String.prototype.capitalize = function() {
    if (this.length) {
      return this[0].toUpperCase() + this.slice(1);
    } else {
      return "";
    }
  };

  String.prototype.repeat = function(count) {
    return new Array(count + 1).join(this);
  };

  window.isEmpty = function(obj) {
    var key;
    for (key in obj) {
      return false;
    }
    return true;
  };

}).call(this);

/* ---- RateLimit.coffee ---- */


(function() {
  var call_after_interval, limits;

  limits = {};

  call_after_interval = {};

  window.RateLimit = function(interval, fn) {
    if (!limits[fn]) {
      call_after_interval[fn] = false;
      fn();
      return limits[fn] = setTimeout((function() {
        if (call_after_interval[fn]) {
          fn();
        }
        delete limits[fn];
        return delete call_after_interval[fn];
      }), interval);
    } else {
      return call_after_interval[fn] = true;
    }
  };

}).call(this);

/* ---- Scrollable.js ---- */


/* via http://jsfiddle.net/elGrecode/00dgurnn/ */

window.initScrollable = function (chrome) {

    var scrollContainer = document.querySelector('.scrollable'),
        scrollContentWrapper = document.querySelector('.scrollable .content-wrapper'),
        scrollContent = document.querySelector('.scrollable .content'),
        contentPosition = 0,
        scrollerBeingDragged = false,
        scroller,
        topPosition,
        normalizedPosition,
        scrollerHeight;

    function calculateScrollerHeight() {
        // *Calculation of how tall scroller should be
        var visibleRatio = scrollContainer.offsetHeight / scrollContentWrapper.scrollHeight;
        if (visibleRatio == 1)
            scroller.style.display = "none";
        else
            scroller.style.display = "block";
        return visibleRatio * scrollContainer.offsetHeight;
    }

    function moveScroller(evt) {
        // Move Scroll bar to top offset
        var scrollPercentage = evt.target.scrollTop / scrollContentWrapper.scrollHeight;
        topPosition = scrollPercentage * (scrollContainer.offsetHeight - 5); // 5px arbitrary offset so scroll bar doesn't move too far beyond content wrapper bounding box
        scroller.style.top = topPosition + 'px';
    }

    function startDrag(evt) {
        normalizedPosition = chrome.point(evt.pageX, evt.pageY).top;
        contentPosition = scrollContentWrapper.scrollTop;
        scrollerBeingDragged = true;
        window.addEventListener('mousemove', scrollBarScroll);
        return false;
    }

    function stopDrag(evt) {
        scrollerBeingDragged = false;
        window.removeEventListener('mousemove', scrollBarScroll);
    }

    function scrollBarScroll(evt) {
        if (scrollerBeingDragged === true) {
            evt.preventDefault();
            var mouseDifferential = chrome.point(evt.pageX, evt.pageY).top - normalizedPosition;
            var scrollEquivalent = mouseDifferential * (scrollContentWrapper.scrollHeight / scrollContainer.offsetHeight);
            scrollContentWrapper.scrollTop = contentPosition + scrollEquivalent;
        }
    }

    function updateHeight() {
        scrollerHeight = calculateScrollerHeight() - 10;
        scroller.style.height = scrollerHeight + 'px';
    }

    function createScroller() {
        // *Creates scroller element and appends to '.scrollable' div
        // create scroller element
        scroller = document.createElement("div");
        scroller.className = 'scroller';

        // determine how big scroller should be based on content
        scrollerHeight = calculateScrollerHeight() - 10;

        if (scrollerHeight / scrollContainer.offsetHeight < 1) {
            // *If there is a need to have scroll bar based on content size
            scroller.style.height = scrollerHeight + 'px';

            // append scroller to scrollContainer div
            scrollContainer.appendChild(scroller);

            // show scroll path divot
            scrollContainer.className += ' showScroll';

            // attach related draggable listeners
            scroller.addEventListener('mousedown', startDrag);
            window.addEventListener('mouseup', stopDrag);
        }

    }

    createScroller();


    // *** Listeners ***
    scrollContentWrapper.addEventListener('scroll', moveScroller);

    return updateHeight;
};

/* ---- Sidebar.coffee ---- */


(function() {
  var Sidebar, wrapper,
    bind = function(fn, me){ return function(){ return fn.apply(me, arguments); }; },
    extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty,
    indexOf = [].indexOf || function(item) { for (var i = 0, l = this.length; i < l; i++) { if (i in this && this[i] === item) return i; } return -1; };

  Sidebar = (function(superClass) {
    extend(Sidebar, superClass);

    function Sidebar(wrapper1) {
      this.wrapper = wrapper1;
      this.unloadGlobe = bind(this.unloadGlobe, this);
      this.displayGlobe = bind(this.displayGlobe, this);
      this.loadGlobe = bind(this.loadGlobe, this);
      this.animDrag = bind(this.animDrag, this);
      this.setHtmlTag = bind(this.setHtmlTag, this);
      this.waitMove = bind(this.waitMove, this);
      this.resized = bind(this.resized, this);
      this.tag = null;
      this.container = null;
      this.opened = false;
      this.width = 420;
      this.console = new Console(this);
      this.fixbutton = $(".fixbutton");
      this.fixbutton_addx = 0;
      this.fixbutton_addy = 0;
      this.fixbutton_initx = 0;
      this.fixbutton_inity = 15;
      this.fixbutton_targetx = 0;
      this.move_lock = null;
      this.page_width = this.wrapper.chrome.width;
      this.page_height = this.wrapper.chrome.height;
      this.frame = $("#inner-iframe");
      this.initFixbutton();
      this.dragStarted = 0;
      this.globe = null;
      this.preload_html = null;
      this.optional_expanded = false;
      this.optional_poll = null;
      this.properties_tab = "overview";
      this.properties_scroll = {};
      this.property_drafts = {};
      this.peer_feedback = "";
      this.peer_map_open = null;
      this.peer_map_saving = false;
      this.sign_publish_menu = null;
      this.pending_actions = {};
      this.translations = {};
      this.update_requested = false;
      this.original_set_xite_info = this.wrapper.setXiteInfo;
      if (window.top.location.hash === "#EpixNet:OpenSidebar") {
        this.startDrag();
        this.moved("x");
        this.fixbutton_targetx = this.fixbutton_initx - this.width;
        this.stopDrag();
      }
    }

    Sidebar.prototype.initFixbutton = function() {
      this.fixbutton.on("mousedown touchstart", (function(_this) {
        return function(e) {
          if (e.button > 0) {
            return;
          }
          e.preventDefault();
          _this.fixbutton.off("click touchend touchcancel");
          _this.dragStarted = +(new Date);
          $(".drag-bg").remove();
          $("<div class='drag-bg'></div>").appendTo(_this.wrapper.chrome.element);
          return $("body").one("mousemove touchmove", function(e) {
            var pointer = _this.pointer(e), position = _this.wrapper.chrome.position(_this.fixbutton[0]);
            _this.fixbutton_addx = position.left - pointer.left;
            _this.fixbutton_addy = position.top - pointer.top;
            return _this.startDrag();
          });
        };
      })(this));
      this.fixbutton.parent().on("click touchend touchcancel", (function(_this) {
        return function(e) {
          if ((+(new Date)) - _this.dragStarted < 100) {
            window.top.location = _this.fixbutton.find(".fixbutton-bg").attr("href");
          }
          return _this.stopDrag();
        };
      })(this));
      this.resized();
      return $(window).on("epixchromechange.sidebar", this.resized);
    };

    Sidebar.prototype.pointer = function(e) {
      var event = e.originalEvent || e;
      var pointer = event.touches && event.touches.length ? event.touches[0] : e;
      return this.wrapper.chrome.point(pointer.pageX, pointer.pageY);
    };

    Sidebar.prototype.resized = function() {
      this.page_width = this.wrapper.chrome.width;
      this.page_height = this.wrapper.chrome.height;
      this.width = this.page_width <= 640 ? this.page_width : 420;
      this.fixbutton_initx = this.page_width - 75;
      // A resize can change both the responsive drawer width and the current
      // console height. Keep the panel translation and handle in the same space.
      if (this.fixbutton.hasClass("dragging")) this.stopDrag();
      this.fixbutton_targetx = this.opened ? this.fixbutton_initx - this.width : this.fixbutton_initx;
      this.fixbutton_targety = this.console.opened ? this.page_height - this.fixbutton_inity - 50 : this.fixbutton_inity;
      this.fixbutton.stop().css({left: this.fixbutton_targetx, top: this.fixbutton_targety});
      if (this.tag) this.tag.css("transform", "translateX(-" + (this.opened ? this.width : 0) + "px)");
      if (this.console.tag) this.console.tag.css("transform", "translateY(" + (this.console.opened ? this.fixbutton_targety - this.fixbutton_inity : 0) + "px)");
      if (this.scrollable && this.container) this.scrollable();
      if (this.globe && this.peer_map_open) this.globe.resize();
      if (window.visible_menu) window.visible_menu.hide();
    };

    Sidebar.prototype.startDrag = function() {
      this.log("startDrag", this.fixbutton_initx, this.fixbutton_inity);
      this.fixbutton_targetx = this.fixbutton_initx;
      this.fixbutton_targety = this.fixbutton_inity;
      this.fixbutton.addClass("dragging");
      if (navigator.userAgent.indexOf('MSIE') !== -1 || navigator.appVersion.indexOf('Trident/') > 0) {
        this.fixbutton.css("pointer-events", "none");
      }
      this.fixbutton.one("click", (function(_this) {
        return function(e) {
          var moved_x, moved_y;
          _this.stopDrag();
          _this.fixbutton.removeClass("dragging");
          moved_x = Math.abs(_this.wrapper.chrome.position(_this.fixbutton[0]).left - _this.fixbutton_initx);
          moved_y = Math.abs(_this.wrapper.chrome.position(_this.fixbutton[0]).top - _this.fixbutton_inity);
          if (moved_x > 5 || moved_y > 10) {
            return e.preventDefault();
          }
        };
      })(this));
      this.fixbutton.parents().on("mousemove touchmove", this.animDrag);
      this.fixbutton.parents().on("mousemove touchmove", this.waitMove);
      return this.fixbutton.parents().one("mouseup touchend touchcancel", (function(_this) {
        return function(e) {
          e.preventDefault();
          return _this.stopDrag();
        };
      })(this));
    };

    Sidebar.prototype.waitMove = function(e) {
      var moved_x, moved_y;
      moved_x = Math.abs(parseInt(this.fixbutton[0].style.left) - this.fixbutton_targetx);
      moved_y = Math.abs(parseInt(this.fixbutton[0].style.top) - this.fixbutton_targety);
      if (moved_x > 5 && (+(new Date)) - this.dragStarted + moved_x > 50) {
        this.moved("x");
        this.fixbutton.stop().animate({
          "top": this.fixbutton_inity
        }, 1000);
        return this.fixbutton.parents().off("mousemove touchmove", this.waitMove);
      } else if (moved_y > 5 && (+(new Date)) - this.dragStarted + moved_y > 50) {
        this.moved("y");
        return this.fixbutton.parents().off("mousemove touchmove", this.waitMove);
      }
    };

    Sidebar.prototype.moved = function(direction) {
      var img;
      this.log("Moved", direction);
      this.move_lock = direction;
      if (direction === "y") {
        $(document.body).addClass("body-console");
        return this.console.createHtmltag();
      }
      this.createHtmltag();
      $(document.body).addClass("body-sidebar");
      this.container.on("mousedown touchend touchcancel", (function(_this) {
        return function(e) {
          if (e.target !== e.currentTarget) {
            return true;
          }
          _this.log("closing");
          if ($(document.body).hasClass("body-sidebar")) {
            _this.close();
            return true;
          }
        };
      })(this));
      this.wrapper.setXiteInfo = (function(_this) {
        return function(xite_info) {
          _this.setXiteInfo(xite_info);
          return _this.original_set_xite_info.apply(_this.wrapper, arguments);
        };
      })(this);
      img = new Image();
      return img.src = "/uimedia/globe/world.jpg";
    };

    Sidebar.prototype.setXiteInfo = function(xite_info) {
      if (this.update_requested && xite_info.update_request_id === this.update_request_id && xite_info.address === this.wrapper.xite_info.address && xite_info.event && xite_info.event[0] === "updated") {
        this.update_requested = false;
        this.setActionBusy("#button-update", false);
        if (xite_info.content_updated === false) this.notify("siteUpdate", "error", "Update failed. No changes were applied.");
        else this.notify("siteUpdate", "done", xite_info.update_applied ? "Xite updated!" : "Xite is already up to date.");
      }
      RateLimit(1500, (function(_this) {
        return function() {
          return _this.updateHtmlTag();
        };
      })(this));
      return RateLimit(30000, (function(_this) {
        return function() {
          return _this.displayGlobe();
        };
      })(this));
    };

    Sidebar.prototype.createHtmltag = function() {
      this.when_loaded = $.Deferred();
      if (!this.container) {
        this.container = $("<div class=\"sidebar-container\"><div class=\"sidebar scrollable\"><div class=\"content-wrapper\"><div class=\"content\">\n</div></div></div></div>");
        this.container.appendTo(this.wrapper.chrome.element);
        this.tag = this.container.find(".sidebar");
        this.updateHtmlTag();
        return this.scrollable = window.initScrollable(this.wrapper.chrome);
      }
    };

    Sidebar.prototype.updateHtmlTag = function() {
      if (this.preload_html) {
        this.setHtmlTag(this.preload_html);
        return this.preload_html = null;
      } else {
        return this.wrapper.ws.cmd("sidebarGetHtmlTag", {}, this.setHtmlTag);
      }
    };

    Sidebar.prototype.setHtmlTag = function(res) {
      if (!this.tag) return;
      if (typeof res !== "string") {
        this.notifyError("properties-load", "Could not load properties", res);
        return;
      }
      var firstRender = this.tag.find(".content").children().length === 0;
      var scroll = this.tag.find(".content-wrapper").scrollTop();
      var focused = document.activeElement;
      var focusedId = focused && this.tag[0].contains(focused) ? focused.id : null;
      var selection = focusedId && typeof focused.selectionStart === "number" ? [focused.selectionStart, focused.selectionEnd] : null;
      if (this.tag.find(".content").children().length === 0) {
        this.log("Creating content");
        this.container.addClass("loaded");
        morphdom(this.tag.find(".content")[0], '<div class="content">' + res + '</div>');
      } else {
        morphdom(this.tag.find(".content")[0], '<div class="content">' + res + '</div>', {
          onBeforeMorphEl: function(from_el, to_el) {
            if (from_el.tagName === "DETAILS") to_el.open = from_el.open;
            // A user-toggled checkbox no longer follows its HTML attribute.
            // Apply the acknowledged server value, including coupled switches
            // and rollbacks after a rejected change. Text drafts stay separate.
            if (from_el.tagName === "INPUT" && from_el.type === "checkbox") from_el.checked = to_el.checked;
            if (from_el.classList.contains("globe") || from_el.className.indexOf("noupdate") >= 0) {
              return false;
            } else {
              return true;
            }
          }
        });
      }
      if (this.tag[0]) {
        var root = this.tag[0].querySelector(".sidebar-properties");
        try { this.translations = JSON.parse(root && root.getAttribute("data-i18n") || "{}"); }
        catch (error) { this.translations = {}; }
      }
      // Keep the server's current-xite URL. On a .epix origin the address
      // lives in the hostname, so rebuilding this link from pathname loses it.
      this.updateOptionalProgress();
      this.applyProperties();
      if (this.opened) this.onOpened();
      if (focusedId) {
        var restored = this.tag[0].querySelector("#" + focusedId);
        if (restored && !restored.closest("[hidden]")) {
          if (document.activeElement !== restored) restored.focus({preventScroll: true});
          if (selection) restored.setSelectionRange(selection[0], selection[1]);
        }
      }
      this.tag.find(".content-wrapper").scrollTop(scroll || 0);
      if (firstRender) this.when_loaded.resolve();
      return this.tag.find("#browse-files");
    };

    Sidebar.prototype.updateContentSelection = function() {
      var path = this.tag.find("#input-contents").val();
      this.tag.find(".contents-content").each(function() {
        var selected = this.getAttribute("data-content-path") === path;
        this.setAttribute("aria-pressed", String(selected));
        this.classList.toggle("selected", selected);
      });
    };

    Sidebar.prototype.selectPropertiesTab = function(tab, rememberScroll) {
      if (["overview", "files", "manage"].indexOf(tab) < 0) tab = "overview";
      var scroll = this.tag.find(".content-wrapper");
      if (rememberScroll) this.properties_scroll[this.properties_tab] = scroll.scrollTop();
      this.properties_tab = tab;
      this.tag.find(".sidebar-tab").each(function() {
        var selected = this.getAttribute("data-tab") === tab;
        this.setAttribute("aria-selected", String(selected));
        this.tabIndex = selected ? 0 : -1;
      });
      this.tag.find(".sidebar-panel").each(function() {
        this.hidden = this.getAttribute("data-panel") !== tab;
      });
      if (rememberScroll) scroll.scrollTop(this.properties_scroll[tab] || 0);
      if (this.scrollable) this.scrollable();
      if (rememberScroll && window.visible_menu) window.visible_menu.hide();
    };

    Sidebar.prototype.savePeerMapPreference = function() {
      if (this.peer_map_saving) return;
      this.peer_map_saving = true;
      var sidebar = this, value = this.peer_map_open;
      this.wrapper.ws.cmd("userSetGlobalSettings", [{sidebar_peer_map_open: value}], function(result) {
        sidebar.peer_map_saving = false;
        if (sidebar.peer_map_open !== value) {
          sidebar.savePeerMapPreference();
        } else if (result !== "ok") {
          sidebar.notifyError("peer-map-setting", "Could not save the peer map preference. Try again.", result);
        }
      });
    };

    Sidebar.prototype.setPeerMapOpen = function(open, save) {
      var changed = this.peer_map_open !== open;
      this.peer_map_open = open;
      if (this.tag) {
        this.tag.find("#sidebar-peer-map-toggle").attr("aria-expanded", String(open));
        this.tag.find(".sidebar-peer-map-state").text(this.t(open ? "Hide" : "Show"));
        this.tag.find("#sidebar-peer-map-panel").prop("hidden", !open);
        if (this.scrollable) this.scrollable();
      }
      if (this.globe) {
        if (open) { this.globe.resize(); this.globe.resume(); if (changed && this.opened) this.displayGlobe(); }
        else this.globe.pause();
      } else if (open && this.opened) {
        this.loadGlobe();
      }
      if (save) this.savePeerMapPreference();
    };

    Sidebar.prototype.applyProperties = function() {
      var sidebar = this;
      if (this.peer_map_open === null) this.peer_map_open = this.tag.find(".sidebar-peer-map").attr("data-open") !== "false";
      this.property_drafts = this.property_drafts || {};
      Object.keys(this.property_drafts).forEach(function(id) {
        sidebar.tag.find("#" + id).val(sidebar.property_drafts[id]);
      });
      Object.keys(this.pending_actions || {}).forEach(function(selector) { sidebar.setActionBusy(selector, true); });
      this.selectPropertiesTab(this.properties_tab || "overview", false);
      this.setPeerMapOpen(this.peer_map_open, false);
      this.updateContentSelection();
      this.tag.find("#form-addpeer button[type=submit]").prop("disabled", !!this.addingPeer).text(this.t(this.addingPeer ? "Adding…" : "Add peer"));
      this.tag.find("#peer-add-status").text(this.peer_feedback || "");
      this.tag.off(".properties").on("click.properties", ".sidebar-tab", function() {
        sidebar.selectPropertiesTab(this.getAttribute("data-tab"), true);
      }).on("keydown.properties", ".sidebar-tab", function(event) {
        var tabs = sidebar.tag.find(".sidebar-tab"), index = tabs.index(this), next;
        if (event.key === "ArrowRight") next = (index + 1) % tabs.length;
        else if (event.key === "ArrowLeft") next = (index + tabs.length - 1) % tabs.length;
        else if (event.key === "Home") next = 0;
        else if (event.key === "End") next = tabs.length - 1;
        else return;
        event.preventDefault();
        sidebar.selectPropertiesTab(tabs[next].getAttribute("data-tab"), true);
        tabs[next].focus();
      }).on("click.properties", "#sidebar-peer-map-toggle", function() {
        sidebar.setPeerMapOpen(!sidebar.peer_map_open, true);
      }).on("input.properties", "#peer-endpoint, #input-xitelimit, #input-autodownload_bigfile_size_limit, #input-contents, #settings-title, #settings-description, #settings-xid-name", function() {
        sidebar.property_drafts[this.id] = this.value;
        if (this.id === "peer-endpoint") { sidebar.peer_feedback = ""; sidebar.tag.find("#peer-add-status").text(""); }
        if (this.id === "input-contents") sidebar.updateContentSelection();
      });
    };

    // Live optional-download panel: keep the collapsible file list's expanded
    // state across morphdom refreshes, wire its toggle, and self-poll the
    // sidebar HTML while a download is in flight (per-file pushes can be sparse
    // for a single big file, so a light timer keeps the bar/spinner moving).
    Sidebar.prototype.updateOptionalProgress = function() {
      var _this = this;
      var list = this.tag.find("#optional-file-list");
      var toggle = this.tag.find("#optional-files-toggle");
      var active = this.tag.find(".optional-progress").length > 0;
      if (active) {
        if (this.optional_expanded) {
          list.addClass("expanded");
          toggle.addClass("expanded");
        }
        toggle.text(this.t(this.optional_expanded ? "Hide files" : "Show files") + " (" + list.children().length + ")");
        toggle.off("click touchend").on("click", function(e) {
          e.preventDefault();
          _this.optional_expanded = !_this.optional_expanded;
          list.toggleClass("expanded", _this.optional_expanded);
          toggle.toggleClass("expanded", _this.optional_expanded);
          toggle.text(_this.t(_this.optional_expanded ? "Hide files" : "Show files") + " (" + list.children().length + ")");
          return false;
        });
        // Only self-poll while the panel is actually on screen; opening the
        // sidebar re-fetches the HTML on its own.
        if (this.opened && !this.optional_poll) {
          this.optional_poll = setTimeout(function() {
            _this.optional_poll = null;
            if (_this.opened) {
              _this.updateHtmlTag();
            }
          }, 1200);
        }
      } else {
        this.optional_expanded = false;
        if (this.optional_poll) {
          clearTimeout(this.optional_poll);
          this.optional_poll = null;
        }
      }
    };

    Sidebar.prototype.animDrag = function(e) {
      var mousex, mousey, overdrag, overdrag_percent, targetx, targety;
      var pointer = this.pointer(e);
      mousex = pointer.left;
      mousey = pointer.top;
      overdrag = this.fixbutton_initx - this.width - mousex;
      if (overdrag > 0) {
        overdrag_percent = 1 + overdrag / 300;
        mousex = (mousex + (this.fixbutton_initx - this.width) * overdrag_percent) / (1 + overdrag_percent);
      }
      targetx = this.fixbutton_initx - mousex - this.fixbutton_addx;
      targety = this.fixbutton_inity - mousey - this.fixbutton_addy;
      if (this.move_lock === "x") {
        targety = this.fixbutton_inity;
      } else if (this.move_lock === "y") {
        targetx = this.fixbutton_initx;
      }
      if (!this.move_lock || this.move_lock === "x") {
        this.fixbutton[0].style.left = (mousex + this.fixbutton_addx) + "px";
        if (this.tag) {
          this.tag[0].style.transform = "translateX(" + (0 - targetx) + "px)";
        }
      }
      if (!this.move_lock || this.move_lock === "y") {
        this.fixbutton[0].style.top = (mousey + this.fixbutton_addy) + "px";
        if (this.console.tag) {
          this.console.tag[0].style.transform = "translateY(" + (0 - targety) + "px)";
        }
      }
      if ((!this.opened && targetx > this.width / 3) || (this.opened && targetx > this.width * 0.9)) {
        this.fixbutton_targetx = this.fixbutton_initx - this.width;
      } else {
        this.fixbutton_targetx = this.fixbutton_initx;
      }
      if ((!this.console.opened && 0 - targety > this.page_height / 10) || (this.console.opened && 0 - targety > this.page_height * 0.8)) {
        return this.fixbutton_targety = this.page_height - this.fixbutton_inity - 50;
      } else {
        return this.fixbutton_targety = this.fixbutton_inity;
      }
    };

    Sidebar.prototype.stopDrag = function() {
      var left, top;
      this.fixbutton.parents().off("mousemove touchmove");
      this.fixbutton.off("mousemove touchmove");
      this.fixbutton.css("pointer-events", "");
      $(".drag-bg").remove();
      if (!this.fixbutton.hasClass("dragging")) {
        return;
      }
      this.fixbutton.removeClass("dragging");
      if (this.fixbutton_targetx !== this.wrapper.chrome.position(this.fixbutton[0]).left || this.fixbutton_targety !== this.wrapper.chrome.position(this.fixbutton[0]).top) {
        if (this.move_lock === "y") {
          top = this.fixbutton_targety;
          left = this.fixbutton_initx;
        }
        if (this.move_lock === "x") {
          top = this.fixbutton_inity;
          left = this.fixbutton_targetx;
        }
        this.fixbutton.stop().animate({
          "left": left,
          "top": top
        }, 500, "easeOutBack", (function(_this) {
          return function() {
            if (_this.fixbutton_targetx === _this.fixbutton_initx) {
              _this.fixbutton.css("left", "auto");
            } else {
              _this.fixbutton.css("left", left);
            }
            return $(".fixbutton-bg").trigger("mouseout");
          };
        })(this));
        this.stopDragX();
        this.console.stopDragY();
      }
      return this.move_lock = null;
    };

    Sidebar.prototype.stopDragX = function() {
      var targetx;
      if (this.fixbutton_targetx === this.fixbutton_initx || this.move_lock === "y") {
        targetx = 0;
        this.opened = false;
      } else {
        targetx = this.width;
        if (this.opened) {
          this.onOpened();
        } else {
          this.when_loaded.done((function(_this) {
            return function() {
              return _this.onOpened();
            };
          })(this));
        }
        this.opened = true;
      }
      if (this.tag) {
        this.tag.css("transition", "0.4s ease-out");
        this.tag.css("transform", "translateX(-" + targetx + "px)").one(transitionEnd, (function(_this) {
          return function() {
            _this.tag.css("transition", "");
            if (!_this.opened) {
              _this.container.remove();
              _this.container = null;
              if (_this.tag) {
                _this.tag.remove();
                return _this.tag = null;
              }
            }
          };
        })(this));
      }
      this.log("stopdrag", "opened:", this.opened);
      if (!this.opened) {
        return this.onClosed();
      }
    };

    Sidebar.prototype.t = function(message) {
      return this.translations && this.translations[message] || message;
    };

    Sidebar.prototype.escapeText = function(value) {
      return String(value).replace(/[&<>"']/g, function(character) {
        return {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[character];
      });
    };

    Sidebar.prototype.notify = function(id, type, message, detail) {
      var text = this.t(message);
      if (detail) text += ": " + detail;
      return this.wrapper.notifications.add(id, type, this.escapeText(text), type === "error" ? 10000 : 5000);
    };

    Sidebar.prototype.notifyError = function(id, message, response) {
      var detail = response && typeof response.error === "string" ? response.error :
        typeof response === "string" ? response : this.t("The request failed. Try again.");
      return this.notify(id, "error", message, detail);
    };

    Sidebar.prototype.setActionBusy = function(selector, busy) {
      this.pending_actions = this.pending_actions || {};
      if (busy) this.pending_actions[selector] = true;
      else delete this.pending_actions[selector];
      if (this.tag) this.tag.find(selector).toggleClass("loading", busy).attr("aria-busy", String(busy)).prop("disabled", busy);
    };

    Sidebar.prototype.runAction = function(selector, command, params, options) {
      options = options || {};
      if (this.pending_actions && this.pending_actions[selector]) return false;
      var sidebar = this;
      this.setActionBusy(selector, true);
      if (options.pending) this.notify(command, "info", options.pending);
      this.wrapper.ws.cmd(command, params, function(response) {
        sidebar.setActionBusy(selector, false);
        var ok = options.accept ? options.accept(response) : response === "ok";
        if (!ok) {
          if (options.failed) options.failed(response);
          sidebar.notifyError(command, options.error || "Action failed", response);
        } else {
          var message = typeof options.success === "function" ? options.success(response) : options.success;
          if (message) sidebar.notify(command, options.type || "done", message);
          if (options.done) options.done(response);
        }
        if (options.refresh !== false && sidebar.tag) sidebar.updateHtmlTag();
      });
      return false;
    };

    Sidebar.prototype.sign = function(inner_path, privatekey) {
      if (this.pending_actions && this.pending_actions["#button-sign-publish"]) return;
      var sidebar = this;
      this.setActionBusy("#button-sign-publish", true);
      this.wrapper.displayProgress("sign", this.escapeText(this.t("Signing") + ": " + inner_path), 0);
      this.wrapper.ws.cmd("siteSign", {privatekey: privatekey, inner_path: inner_path, update_changed_files: true}, function(res) {
        sidebar.setActionBusy("#button-sign-publish", false);
        if (res === "ok") {
          sidebar.wrapper.displayProgress("sign", sidebar.escapeText(inner_path + ": " + sidebar.t("Signed")), 100);
          if (sidebar.tag) sidebar.updateHtmlTag();
        } else {
          sidebar.wrapper.displayProgress("sign", sidebar.escapeText(sidebar.t("Signing failed")), -1);
          sidebar.notifyError("sign-error", "Signing failed", res);
        }
      });
    };

    Sidebar.prototype.publish = function(inner_path, privatekey, sign) {
      // The backend reports actual peer acceptance. Do not add a second
      // success message for its acknowledgement of a queued publish.
      return this.runAction("#button-sign-publish", "sitePublish", {
        privatekey: privatekey, inner_path: inner_path, sign: sign !== false, update_changed_files: true
      }, {error: "Publishing failed"});
    };

    Sidebar.prototype.withSigningKey = function(inner_path, action) {
      if (this.signing_key_pending || (this.pending_actions && this.pending_actions["#button-sign-publish"])) return;
      this.signing_key_pending = true;
      var sidebar = this;
      function proceed(key) { sidebar.signing_key_pending = false; action(key); }
      this.wrapper.ws.cmd("fileRules", {inner_path: inner_path}, function(rules) {
        if (!rules || !Array.isArray(rules.signers)) {
          sidebar.signing_key_pending = false;
          sidebar.notifyError("sign-rules", "Could not read signing rules", rules);
          return;
        }
        if (rules.signers.indexOf(sidebar.wrapper.xite_info.auth_address) >= 0) proceed(null);
        else if (sidebar.wrapper.xite_info.privatekey) proceed("stored");
        else {
          // Closing a wrapper prompt does not invoke its callback. Release
          // the lookup guard so dismissing it never strands signing.
          sidebar.signing_key_pending = false;
          sidebar.wrapper.displayPrompt(sidebar.t("Enter your private key:"), "password", sidebar.t("Sign"), "", function(privatekey) {
            if (privatekey) action(privatekey);
          });
        }
      });
    };

    Sidebar.prototype.saveSettings = function() {
      if (this.pending_actions && this.pending_actions["#button-settings"]) return false;
      var sidebar = this, submitted = {};
      ["settings-title", "settings-description", "settings-xid-name"].forEach(function(id) { submitted[id] = sidebar.tag.find("#" + id).val(); });
      this.setActionBusy("#button-settings", true);
      this.wrapper.ws.cmd("fileGet", "content.json", function(original) {
        var data;
        try {
          if (typeof original !== "string") throw new Error(original && original.error || "content.json is unavailable");
          data = JSON.parse(original);
          if (!data || typeof data !== "object" || Array.isArray(data)) throw new Error("content.json must contain an object");
        } catch (error) {
          sidebar.setActionBusy("#button-settings", false);
          sidebar.notifyError("file-write", "Could not read xite settings", {error: error.message});
          return;
        }
        data.title = submitted["settings-title"];
        data.description = submitted["settings-description"];
        var name = submitted["settings-xid-name"].trim();
        if (name) data.domain = name; else delete data.domain;
        var encoded = btoa(unescape(encodeURIComponent(JSON.stringify(data, null, "\t"))));
        var signed = !!sidebar.wrapper.xite_info.privatekey;
        // Root metadata uses fileWrite followed by siteSign. fileWriteSign is
        // reserved for child data files and cannot sign a root manifest.
        sidebar.wrapper.ws.cmd("fileWrite", ["content.json", encoded, true], function(response) {
          if (response !== "ok") {
            sidebar.setActionBusy("#button-settings", false);
            sidebar.notifyError("file-write", "Could not save xite settings", response);
            return;
          }
          function finished(signResult) {
            sidebar.setActionBusy("#button-settings", false);
            if (signed && signResult !== "ok") {
              sidebar.notifyError("file-write", "Settings saved, but signing failed. Sign again before publishing.", signResult);
              return;
            }
            Object.keys(submitted).forEach(function(id) { if (sidebar.property_drafts[id] === submitted[id]) delete sidebar.property_drafts[id]; });
            sidebar.notify("file-write", "done", signed ? "Xite settings saved and signed." : "Settings saved. Sign and publish to share changes.");
            if (sidebar.tag) sidebar.updateHtmlTag();
          }
          if (signed) sidebar.wrapper.ws.cmd("siteSign", {inner_path: "content.json", privatekey: "stored", update_changed_files: true}, finished);
          else finished();
        });
      });
      return false;
    };

    Sidebar.prototype.handleXiteDeleteClick = function() {
      var sidebar = this;
      var hasKey = this.wrapper.xite_info.privatekey;
      var question = this.escapeText(this.t("Are you sure?"));
      if (hasKey) question += "<br>" + this.escapeText(this.t("This xite has a saved private key"));
      var options = hasKey ? [this.t("Forget private key and delete xite")] : [this.t("Delete this xite"), this.t("Blacklist")];
      function remove() {
        sidebar.runAction("#button-delete", "siteDelete", sidebar.wrapper.xite_info.address, {
          refresh: false, error: "Could not delete xite", done: function() {
            document.location = $(".fixbutton-bg").attr("href");
          }
        });
      }
      this.wrapper.displayConfirm(question, options, function(confirmed) {
        if (confirmed === 1) remove();
        else if (confirmed === 2) sidebar.wrapper.displayPrompt(sidebar.t("Blacklist this xite"), "text", sidebar.t("Delete and Blacklist"), sidebar.t("Reason"), function(reason) {
          if (reason === null || reason === false) return;
          sidebar.runAction("#button-delete", "siteblockAdd", [sidebar.wrapper.xite_info.address, reason], {
            refresh: false, error: "Could not blacklist xite", done: remove
          });
        });
      });
    };

    Sidebar.prototype.addPeer = function() {
      var input = this.tag.find("#peer-endpoint");
      var peer = input.val().trim();
      if (!peer || this.addingPeer) return;
      this.addingPeer = true;
      this.peer_feedback = "";
      this.tag.find("#form-addpeer button[type=submit]").prop("disabled", true).text(this.t("Adding…"));
      this.tag.find("#peer-add-status").text("");
      var sidebar = this;
      this.wrapper.ws.cmd("peerAdd", {
        peer: peer,
        site_address: this.wrapper.xite_info.address
      }, function(res) {
        sidebar.addingPeer = false;
        if (sidebar.tag) sidebar.tag.find("#form-addpeer button[type=submit]").prop("disabled", false).text(sidebar.t("Add peer"));
        if (res === "updated") {
          if (input.val().trim() === peer && (!Object.prototype.hasOwnProperty.call(sidebar.property_drafts, "peer-endpoint") || sidebar.property_drafts["peer-endpoint"].trim() === peer)) {
            input.val("");
            delete sidebar.property_drafts["peer-endpoint"];
          }
          sidebar.peer_feedback = sidebar.t("Peer added.");
          if (sidebar.tag) sidebar.tag.find("#peer-add-status").text(sidebar.peer_feedback);
          sidebar.notify("peer-add", "done", "Peer added");
          sidebar.updateHtmlTag();
        } else {
          var detail = res && typeof res.error === "string" ? res.error : sidebar.t("Could not add this peer");
          sidebar.peer_feedback = detail;
          if (sidebar.tag) sidebar.tag.find("#peer-add-status").text(detail);
          sidebar.notify("peer-add", "error", detail);
        }
      });
    };

    Sidebar.prototype.onOpened = function() {
      var menu;
      this.log("Opened");
      this.scrollable();
      this.tag.find("#checkbox-owned, #checkbox-autodownloadoptional").off("click touchend").on("click", (function(_this) {
        return function() {
          return setTimeout((function() {
            return _this.scrollable();
          }), 300);
        };
      })(this));
      var sidebar = this;
      function bind(selector, command, params, options) {
        sidebar.tag.find(selector).off("click touchend").on("click", function() {
          if (sidebar.pending_actions && sidebar.pending_actions[selector]) return false;
          return sidebar.runAction(selector, command, typeof params === "function" ? params() : params, options);
        });
      }
      this.tag.find("#button-xitelimit").off("click").on("click", function() {
        var value = sidebar.tag.find("#input-xitelimit").val();
        return sidebar.runAction("#button-xitelimit", "siteSetLimit", value, {
          success: "Xite storage limit modified!", error: "Could not save storage limit", done: function() {
            if (sidebar.property_drafts["input-xitelimit"] === value) delete sidebar.property_drafts["input-xitelimit"];
          }
        });
      });
      this.tag.find("#button-autodownload_bigfile_size_limit").off("click touchend").on("click", function() {
        var value = sidebar.tag.find("#input-autodownload_bigfile_size_limit").val();
        return sidebar.runAction("#button-autodownload_bigfile_size_limit", "siteSetAutodownloadBigfileLimit", {limit: value}, {
          success: "Automatic download limit saved", error: "Could not save automatic download limit", done: function() {
            if (sidebar.property_drafts["input-autodownload_bigfile_size_limit"] === value) delete sidebar.property_drafts["input-autodownload_bigfile_size_limit"];
          }
        });
      });
      bind("#button-autodownload_previous", "siteDownloadOptionalPrevious", {}, {
        error: "Could not download previous files", type: "info", accept: function(res) { return res && (res.status === "started" || res.status === "complete"); },
        success: function(res) { return res.status === "complete" ? "All eligible optional files are already downloaded." : "Optional file download started."; }
      });
      bind("#button-dbreload", "dbReload", [], {success: "Database schema reloaded!", error: "Could not reload database schema"});
      bind("#button-dbrebuild", "dbRebuild", [], {pending: "Rebuilding database", success: "Database rebuilt!", error: "Could not rebuild database"});
      bind("#button-update", "siteUpdate", function() {
        sidebar.update_requested = true;
        sidebar.update_request_id = "sidebar-" + Date.now() + "-" + Math.random().toString(36).slice(2);
        return {address: sidebar.wrapper.xite_info.address, update_request_id: sidebar.update_request_id};
      }, {
        refresh: false, type: "info", success: function() { return sidebar.update_requested ? "Checking for updates" : null; }, error: "Could not start update",
        accept: function(res) { return res === "Updated" || res === "ok"; }, failed: function() { sidebar.update_requested = false; },
        done: function() { sidebar.setActionBusy("#button-update", sidebar.update_requested); }
      });
      [["#button-pause", "sitePause"], ["#button-resume", "siteResume"],
       ["#button-favourite", "siteFavourite"], ["#button-unfavourite", "siteUnfavourite"]].forEach(function(item) {
        bind(item[0], item[1], function() { return sidebar.wrapper.xite_info.address; }, {error: "Could not change xite settings"});
      });
      this.tag.find("#button-delete").off("click touchend").on("click", function() { sidebar.handleXiteDeleteClick(); return false; });
      this.tag.find("#checkbox-owned").off("click touchend change").on("change", function() {
        var owned = this.checked;
        sidebar.runAction("#checkbox-owned", "siteSetOwned", [owned], {error: "Could not change ownership", done: function() {
          if (!owned || sidebar.wrapper.xite_info.privatekey) return;
          sidebar.runAction("#privatekey-add", "siteRecoverPrivatekey", [], {
            success: "Private key recovered from master seed", error: "Private key could not be recovered. Add a signing key to publish."
          });
        }});
        setTimeout(function() { if (sidebar.tag) sidebar.scrollable(); }, 300);
      });
      [["#checkbox-autodownloadoptional", "siteSetAutodownloadoptional"], ["#checkbox-downloadoptional", "siteSetDownloadoptional"]].forEach(function(item) {
        sidebar.tag.find(item[0]).off("click touchend change").on("change", function() {
          sidebar.runAction(item[0], item[1], [this.checked], {error: "Could not change optional download settings"});
        });
      });
      bind("#button-identity", "certXid", {}, {error: "Could not change identity", accept: function(res) { return res === "ok" || res === "Not changed"; }});
      bind("#button-cert-disconnect", "certSet", [""], {success: "Certificate disconnected", error: "Could not disconnect identity"});
      this.tag.find("#privatekey-add").off("click touchend").on("click", function() {
        sidebar.wrapper.displayPrompt(sidebar.t("Enter your private key:"), "password", sidebar.t("Save"), "", function(key) {
          if (!key) return;
          sidebar.runAction("#privatekey-add", "userSetSitePrivatekey", [key], {success: "Private key saved for xite signing", error: "Private key not saved"});
        });
        return false;
      });
      this.tag.find("#privatekey-forget").off("click touchend").on("click", function() {
        sidebar.wrapper.displayConfirm(sidebar.t("Remove saved private key for this xite?"), sidebar.t("Forget"), function(confirmed) {
          if (confirmed) sidebar.runAction("#privatekey-forget", "userSetSitePrivatekey", [""], {success: "Saved private key removed", error: "Could not forget private key"});
        });
        return false;
      });
      this.tag.find("#button-settings").off("click touchend").on("click", function() { return sidebar.saveSettings(); });
      bind("#link-directory", "serverShowdirectory", function() { return ["xite", sidebar.wrapper.xite_info.address]; }, {refresh: false, error: "Could not open directory"});
      this.tag.find("#form-addpeer").off("submit").on("submit", (function(_this) {
        return function(e) {
          e.preventDefault();
          _this.addPeer();
          return false;
        };
      })(this));
      this.tag.find("#link-copypeers").off("click touchend").on("click", function(event) {
        var text = event.currentTarget.href;
        var hasPeers = new URL(text).searchParams.get("epixnet_peers");
        function copied() { sidebar.notify("copy", "done", hasPeers ? "Xite address with peers copied to your clipboard" : "Xite link copied. No shareable peers are available."); }
        function fallback() {
          var copiedText = false;
          function handler(event) {
            if (!event.clipboardData) return;
            event.clipboardData.setData("text/plain", text);
            event.preventDefault();
            copiedText = true;
          }
          document.addEventListener("copy", handler, true);
          try { document.execCommand("copy"); }
          catch (error) { copiedText = false; }
          finally { document.removeEventListener("copy", handler, true); }
          if (copiedText) copied();
          else sidebar.notify("copy", "error", "Could not copy the link. Check clipboard permissions.");
        }
        if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(copied, fallback);
        else fallback();
        return false;
      });
      $(document).off("click.sidebarPublish").on("click.sidebarPublish", (function(_this) {
        return function() {
          var ref, ref1;
          if ((ref = _this.tag) != null) {
            ref.find("#button-sign-publish-menu").removeClass("visible");
          }
          return (ref1 = _this.tag) != null ? ref1.find(".contents + .flex").removeClass("sign-publish-flex") : void 0;
        };
      })(this));
      this.tag.find(".contents-content").off("click touchend").on("click", (function(_this) {
        return function(e) {
          var path = e.currentTarget.getAttribute("data-content-path") || e.currentTarget.textContent;
          _this.tag.find("#input-contents").val(path);
          _this.property_drafts["input-contents"] = path;
          _this.updateContentSelection();
          return false;
        };
      })(this));
      menu = this.sign_publish_menu;
      if (!menu || menu.button[0] !== this.tag.find("#menu-sign-publish")[0]) {
        if (menu) { menu.hide(); menu.elem.remove(); }
        menu = this.sign_publish_menu = new Menu(this.tag.find("#menu-sign-publish"), this.wrapper.chrome);
      }
      menu.elem.css("margin-top", "-130px");
      if (!menu.items.length) {
      menu.addItem(this.t("Sign"), (function(_this) {
        return function() {
          var inner_path;
          inner_path = _this.tag.find("#input-contents").val();
          _this.withSigningKey(inner_path, function(key) { _this.sign(inner_path, key); });
          _this.tag.find(".contents + .flex").removeClass("active");
          return menu.hide();
        };
      })(this));
      menu.addItem(this.t("Publish"), (function(_this) {
        return function() {
          var inner_path;
          inner_path = _this.tag.find("#input-contents").val();
          _this.publish(inner_path, null, false);
          _this.tag.find(".contents + .flex").removeClass("active");
          return menu.hide();
        };
      })(this));
      }
      this.tag.find("#menu-sign-publish").off("click touchend").on("click", (function(_this) {
        return function() {
          if (window.visible_menu === menu) {
            _this.tag.find(".contents + .flex").removeClass("active");
            menu.hide();
          } else {
            _this.tag.find(".contents + .flex").addClass("active");
            menu.show();
          }
          return false;
        };
      })(this));
      $("body").off("click.sidebarPublish").on("click.sidebarPublish", (function(_this) {
        return function() {
          if (_this.tag) {
            return _this.tag.find(".contents + .flex").removeClass("active");
          }
        };
      })(this));
      this.tag.find("#button-sign-publish").off("click touchend").on("click", (function(_this) {
        return function() {
          var inner_path;
          inner_path = _this.tag.find("#input-contents").val();
          _this.withSigningKey(inner_path, function(key) { _this.publish(inner_path, key); });
          return false;
        };
      })(this));
      this.tag.find(".close").off("click touchend").on("click", (function(_this) {
        return function(e) {
          _this.close();
          return false;
        };
      })(this));
      return this.loadGlobe();
    };

    Sidebar.prototype.close = function() {
      this.move_lock = "x";
      this.startDrag();
      return this.stopDrag();
    };

    Sidebar.prototype.onClosed = function() {
      if (this.sign_publish_menu) {
        this.sign_publish_menu.hide();
        this.sign_publish_menu.elem.remove();
        this.sign_publish_menu = null;
      }
      $(document).off(".sidebarPublish");
      $("body").off(".sidebarPublish");
      $(document.body).css("transition", "0.6s ease-in-out").removeClass("body-sidebar").on(transitionEnd, (function(_this) {
        return function(e) {
          if (e.target === document.body && !$(document.body).hasClass("body-sidebar") && !$(document.body).hasClass("body-console")) {
            $(document.body).css("height", "auto").css("perspective", "").css("will-change", "").css("transition", "").off(transitionEnd);
            return _this.unloadGlobe();
          }
        };
      })(this));
      return this.wrapper.setXiteInfo = this.original_set_xite_info;
    };

    Sidebar.prototype.loadGlobe = function() {
      if (!this.tag || !this.peer_map_open || !this.tag.find(".globe").length) return;
      if (this.globe) { this.globe.resize(); this.globe.resume(); return; }
      if (!this.globe_script_loading) {
        return setTimeout(((function(_this) {
          return function() {
            var script_tag;
            if (!_this.tag || !_this.opened || !_this.peer_map_open || _this.globe_script_loading) return;
            if (typeof DAT === "undefined") {
              _this.globe_script_loading = true;
              script_tag = $("<script>");
              script_tag.attr("nonce", _this.wrapper.script_nonce);
              script_tag.attr("src", "/uimedia/globe/all.js");
              script_tag.on("load", function() { _this.globe_script_loading = false; _this.displayGlobe(); });
              script_tag.on("error", function() {
                _this.globe_script_loading = false;
                if (_this.tag) _this.tag.find(".globe").removeClass("loading").addClass("error").text("The peer map could not be loaded.");
              });
              return document.head.appendChild(script_tag[0]);
            } else {
              return _this.displayGlobe();
            }
          };
        })(this)), 150);
      }
    };

    Sidebar.prototype.displayGlobe = function() {
      var _this = this;
      if (!this.tag || !this.opened || !this.peer_map_open) return;
      // Draw the sphere first, then drop peer points in when they arrive, so the
      // globe appears immediately instead of waiting on the sidebarGetPeers round
      // trip. The texture (world.jpg) is loaded once, by three.js, not twice.
      var addPeers = function() {
        return _this.wrapper.ws.cmd("sidebarGetPeers", [], function(globe_data) {
          var ref;
          if (!_this.globe) {
            return;
          }
          try {
            if (_this.globe.points) {
              _this.globe.scene.remove(_this.globe.points);
              _this.globe.points.geometry.dispose();
              _this.globe.points.material.dispose();
              _this.globe._baseGeometry = null;
            }
            _this.globe.addData(globe_data, {
              format: 'magnitude',
              name: "hello",
              animated: false
            });
            _this.globe.createPoints();
          } catch (error) {
            console.log("globe data error", error);
          }
          return (ref = _this.tag) != null ? ref.find(".globe").removeClass("loading") : void 0;
        });
      };
      if (this.globe) {
        return addPeers();
      }
      if (typeof DAT === "undefined") {
        return;
      }
      try {
        this.globe = new DAT.Globe(this.tag.find(".globe")[0], {
          "imgDir": "/uimedia/globe/",
          "controls": this.tag.find(".sidebar-peer-map")[0]
        });
        this.globe.animate();
      } catch (error) {
        console.log("WebGL error", error);
        if (this.tag != null) {
          this.tag.find(".globe").addClass("error").text("WebGL not supported");
        }
        return;
      }
      this.tag.find(".globe").removeClass("loading");
      return addPeers();
    };

    Sidebar.prototype.unloadGlobe = function() {
      if (!this.globe) {
        return false;
      }
      this.globe.unload();
      return this.globe = null;
    };

    return Sidebar;

  })(Class);

  wrapper = window.wrapper;

  setTimeout((function() {
    return window.sidebar = new Sidebar(wrapper);
  }), 500);

  window.transitionEnd = 'transitionend webkitTransitionEnd oTransitionEnd otransitionend';

}).call(this);


/* ---- morphdom.js ---- */


(function(f){if(typeof exports==="object"&&typeof module!=="undefined"){module.exports=f()}else if(typeof define==="function"&&define.amd){define([],f)}else{var g;if(typeof window!=="undefined"){g=window}else if(typeof global!=="undefined"){g=global}else if(typeof self!=="undefined"){g=self}else{g=this}g.morphdom = f()}})(function(){var define,module,exports;return (function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);var f=new Error("Cannot find module '"+o+"'");throw f.code="MODULE_NOT_FOUND",f}var l=n[o]={exports:{}};t[o][0].call(l.exports,function(e){var n=t[o][1][e];return s(n?n:e)},l,l.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({1:[function(require,module,exports){
var specialElHandlers = {
    /**
     * Needed for IE. Apparently IE doesn't think
     * that "selected" is an attribute when reading
     * over the attributes using selectEl.attributes
     */
    OPTION: function(fromEl, toEl) {
        if ((fromEl.selected = toEl.selected)) {
            fromEl.setAttribute('selected', '');
        } else {
            fromEl.removeAttribute('selected', '');
        }
    },
    /**
     * The "value" attribute is special for the <input> element
     * since it sets the initial value. Changing the "value"
     * attribute without changing the "value" property will have
     * no effect since it is only used to the set the initial value.
     * Similar for the "checked" attribute.
     */
    /*INPUT: function(fromEl, toEl) {
        fromEl.checked = toEl.checked;
        fromEl.value = toEl.value;

        if (!toEl.hasAttribute('checked')) {
            fromEl.removeAttribute('checked');
        }

        if (!toEl.hasAttribute('value')) {
            fromEl.removeAttribute('value');
        }
    }*/
};

function noop() {}

/**
 * Loop over all of the attributes on the target node and make sure the
 * original DOM node has the same attributes. If an attribute
 * found on the original node is not on the new node then remove it from
 * the original node
 * @param  {HTMLElement} fromNode
 * @param  {HTMLElement} toNode
 */
function morphAttrs(fromNode, toNode) {
    var attrs = toNode.attributes;
    var i;
    var attr;
    var attrName;
    var attrValue;
    var foundAttrs = {};

    for (i=attrs.length-1; i>=0; i--) {
        attr = attrs[i];
        if (attr.specified !== false) {
            attrName = attr.name;
            attrValue = attr.value;
            foundAttrs[attrName] = true;

            if (fromNode.getAttribute(attrName) !== attrValue) {
                fromNode.setAttribute(attrName, attrValue);
            }
        }
    }

    // Delete any extra attributes found on the original DOM element that weren't
    // found on the target element.
    attrs = fromNode.attributes;

    for (i=attrs.length-1; i>=0; i--) {
        attr = attrs[i];
        if (attr.specified !== false) {
            attrName = attr.name;
            if (!foundAttrs.hasOwnProperty(attrName)) {
                fromNode.removeAttribute(attrName);
            }
        }
    }
}

/**
 * Copies the children of one DOM element to another DOM element
 */
function moveChildren(from, to) {
    var curChild = from.firstChild;
    while(curChild) {
        var nextChild = curChild.nextSibling;
        to.appendChild(curChild);
        curChild = nextChild;
    }
    return to;
}

function morphdom(fromNode, toNode, options) {
    if (!options) {
        options = {};
    }

    if (typeof toNode === 'string') {
        var newBodyEl = document.createElement('body');
        newBodyEl.innerHTML = toNode;
        toNode = newBodyEl.childNodes[0];
    }

    var savedEls = {}; // Used to save off DOM elements with IDs
    var unmatchedEls = {};
    var onNodeDiscarded = options.onNodeDiscarded || noop;
    var onBeforeMorphEl = options.onBeforeMorphEl || noop;
    var onBeforeMorphElChildren = options.onBeforeMorphElChildren || noop;

    function removeNodeHelper(node, nestedInSavedEl) {
        var id = node.id;
        // If the node has an ID then save it off since we will want
        // to reuse it in case the target DOM tree has a DOM element
        // with the same ID
        if (id) {
            savedEls[id] = node;
        } else if (!nestedInSavedEl) {
            // If we are not nested in a saved element then we know that this node has been
            // completely discarded and will not exist in the final DOM.
            onNodeDiscarded(node);
        }

        if (node.nodeType === 1) {
            var curChild = node.firstChild;
            while(curChild) {
                removeNodeHelper(curChild, nestedInSavedEl || id);
                curChild = curChild.nextSibling;
            }
        }
    }

    function walkDiscardedChildNodes(node) {
        if (node.nodeType === 1) {
            var curChild = node.firstChild;
            while(curChild) {


                if (!curChild.id) {
                    // We only want to handle nodes that don't have an ID to avoid double
                    // walking the same saved element.

                    onNodeDiscarded(curChild);

                    // Walk recursively
                    walkDiscardedChildNodes(curChild);
                }

                curChild = curChild.nextSibling;
            }
        }
    }

    function removeNode(node, parentNode, alreadyVisited) {
        parentNode.removeChild(node);

        if (alreadyVisited) {
            if (!node.id) {
                onNodeDiscarded(node);
                walkDiscardedChildNodes(node);
            }
        } else {
            removeNodeHelper(node);
        }
    }

    function morphEl(fromNode, toNode, alreadyVisited) {
        if (toNode.id) {
            // If an element with an ID is being morphed then it is will be in the final
            // DOM so clear it out of the saved elements collection
            delete savedEls[toNode.id];
        }

        if (onBeforeMorphEl(fromNode, toNode) === false) {
            return;
        }

        morphAttrs(fromNode, toNode);

        if (onBeforeMorphElChildren(fromNode, toNode) === false) {
            return;
        }

        var curToNodeChild = toNode.firstChild;
        var curFromNodeChild = fromNode.firstChild;
        var curToNodeId;

        var fromNextSibling;
        var toNextSibling;
        var savedEl;
        var unmatchedEl;

        outer: while(curToNodeChild) {
            toNextSibling = curToNodeChild.nextSibling;
            curToNodeId = curToNodeChild.id;

            while(curFromNodeChild) {
                var curFromNodeId = curFromNodeChild.id;
                fromNextSibling = curFromNodeChild.nextSibling;

                if (!alreadyVisited) {
                    if (curFromNodeId && (unmatchedEl = unmatchedEls[curFromNodeId])) {
                        unmatchedEl.parentNode.replaceChild(curFromNodeChild, unmatchedEl);
                        morphEl(curFromNodeChild, unmatchedEl, alreadyVisited);
                        curFromNodeChild = fromNextSibling;
                        continue;
                    }
                }

                var curFromNodeType = curFromNodeChild.nodeType;

                if (curFromNodeType === curToNodeChild.nodeType) {
                    var isCompatible = false;

                    if (curFromNodeType === 1) { // Both nodes being compared are Element nodes
                        if (curFromNodeChild.tagName === curToNodeChild.tagName) {
                            // We have compatible DOM elements
                            if (curFromNodeId || curToNodeId) {
                                // If either DOM element has an ID then we handle
                                // those differently since we want to match up
                                // by ID
                                if (curToNodeId === curFromNodeId) {
                                    isCompatible = true;
                                }
                            } else {
                                isCompatible = true;
                            }
                        }

                        if (isCompatible) {
                            // We found compatible DOM elements so add a
                            // task to morph the compatible DOM elements
                            morphEl(curFromNodeChild, curToNodeChild, alreadyVisited);
                        }
                    } else if (curFromNodeType === 3) { // Both nodes being compared are Text nodes
                        isCompatible = true;
                        curFromNodeChild.nodeValue = curToNodeChild.nodeValue;
                    }

                    if (isCompatible) {
                        curToNodeChild = toNextSibling;
                        curFromNodeChild = fromNextSibling;
                        continue outer;
                    }
                }

                // No compatible match so remove the old node from the DOM
                removeNode(curFromNodeChild, fromNode, alreadyVisited);

                curFromNodeChild = fromNextSibling;
            }

            if (curToNodeId) {
                if ((savedEl = savedEls[curToNodeId])) {
                    morphEl(savedEl, curToNodeChild, true);
                    curToNodeChild = savedEl; // We want to append the saved element instead
                } else {
                    // The current DOM element in the target tree has an ID
                    // but we did not find a match in any of the corresponding
                    // siblings. We just put the target element in the old DOM tree
                    // but if we later find an element in the old DOM tree that has
                    // a matching ID then we will replace the target element
                    // with the corresponding old element and morph the old element
                    unmatchedEls[curToNodeId] = curToNodeChild;
                }
            }

            // If we got this far then we did not find a candidate match for our "to node"
            // and we exhausted all of the children "from" nodes. Therefore, we will just
            // append the current "to node" to the end
            fromNode.appendChild(curToNodeChild);

            curToNodeChild = toNextSibling;
            curFromNodeChild = fromNextSibling;
        }

        // We have processed all of the "to nodes". If curFromNodeChild is non-null then
        // we still have some from nodes left over that need to be removed
        while(curFromNodeChild) {
            fromNextSibling = curFromNodeChild.nextSibling;
            removeNode(curFromNodeChild, fromNode, alreadyVisited);
            curFromNodeChild = fromNextSibling;
        }

        var specialElHandler = specialElHandlers[fromNode.tagName];
        if (specialElHandler) {
            specialElHandler(fromNode, toNode);
        }
    }

    var morphedNode = fromNode;
    var morphedNodeType = morphedNode.nodeType;
    var toNodeType = toNode.nodeType;

    // Handle the case where we are given two DOM nodes that are not
    // compatible (e.g. <div> --> <span> or <div> --> TEXT)
    if (morphedNodeType === 1) {
        if (toNodeType === 1) {
            if (morphedNode.tagName !== toNode.tagName) {
                onNodeDiscarded(fromNode);
                morphedNode = moveChildren(morphedNode, document.createElement(toNode.tagName));
            }
        } else {
            // Going from an element node to a text node
            return toNode;
        }
    } else if (morphedNodeType === 3) { // Text node
        if (toNodeType === 3) {
            morphedNode.nodeValue = toNode.nodeValue;
            return morphedNode;
        } else {
            onNodeDiscarded(fromNode);
            // Text node to something else
            return toNode;
        }
    }

    morphEl(morphedNode, toNode, false);

    // Fire the "onNodeDiscarded" event for any saved elements
    // that never found a new home in the morphed DOM
    for (var savedElId in savedEls) {
        if (savedEls.hasOwnProperty(savedElId)) {
            var savedEl = savedEls[savedElId];
            onNodeDiscarded(savedEl);
            walkDiscardedChildNodes(savedEl);
        }
    }

    if (morphedNode !== fromNode && fromNode.parentNode) {
        fromNode.parentNode.replaceChild(morphedNode, fromNode);
    }

    return morphedNode;
}

module.exports = morphdom;
},{}]},{},[1])(1)
});
