/**
 * dat.globe Javascript WebGL Globe Toolkit
 * http://dataarts.github.com/dat.globe
 *
 * Copyright 2011 Data Arts Team, Google Creative Lab
 *
 * Licensed under the Apache License, Version 2.0 (the 'License');
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */

var DAT = DAT || {};

DAT.Globe = function(container, opts) {
  opts = opts || {};

  var colorFn = opts.colorFn || function(x) {
    var c = new THREE.Color();
    c.setHSL( ( 0.5 - (x * 2) ), Math.max(0.8, 1.0 - (x * 3)), 0.5 );
    return c;
  };
  var imgDir = opts.imgDir || '/globe/';

  var Shaders = {
    'earth' : {
      uniforms: {
        'texture': { type: 't', value: null },
        'waterScale': { type: 'f', value: 28 },
        'landColor': { type: 'c', value: new THREE.Color(0x59636E) },
        'waterColor': { type: 'c', value: new THREE.Color(0xB8C3CE) },
        'rimColor': { type: 'c', value: new THREE.Color(0xAAB5C0) }
      },
      vertexShader: [
        'varying vec3 vNormal;',
        'varying vec2 vUv;',
        'void main() {',
          'gl_Position = projectionMatrix * modelViewMatrix * vec4( position, 1.0 );',
          'vNormal = normalize( normalMatrix * normal );',
          'vUv = uv;',
        '}'
      ].join('\n'),
      fragmentShader: [
        'uniform sampler2D texture;',
        'uniform float waterScale;',
        'uniform vec3 landColor;',
        'uniform vec3 waterColor;',
        'uniform vec3 rimColor;',
        'varying vec3 vNormal;',
        'varying vec2 vUv;',
        'void main() {',
          // Flatten ocean relief in light mode while retaining the darker map texture.
          'float water = clamp( texture2D( texture, vUv ).r * waterScale, 0.0, 1.0 );',
          'float facing = max( dot( vNormal, vec3( 0.0, 0.0, 1.0 ) ), 0.0 );',
          'vec3 surface = mix( landColor, waterColor, water ) * ( 0.82 + 0.18 * facing );',
          'float rim = pow( 1.0 - facing, 3.0 ) * 0.22;',
          'gl_FragColor = vec4( mix( surface, rimColor, rim ), 1.0 );',
        '}'
      ].join('\n')
    },
    'atmosphere' : {
      uniforms: {
        'rimColor': { type: 'c', value: new THREE.Color(0xAAB5C0) }
      },
      vertexShader: [
        'varying vec3 vNormal;',
        'void main() {',
          'vNormal = normalize( normalMatrix * normal );',
          'gl_Position = projectionMatrix * modelViewMatrix * vec4( position, 1.0 );',
        '}'
      ].join('\n'),
      fragmentShader: [
        'uniform vec3 rimColor;',
        'varying vec3 vNormal;',
        'void main() {',
          'float intensity = pow( max( 0.0, 0.8 - dot( vNormal, vec3( 0.0, 0.0, 1.0 ) ) ), 12.0 );',
          'gl_FragColor = vec4( rimColor, min( intensity * 0.18, 0.24 ) );',
        '}'
      ].join('\n')
    }
  };

  var camera, scene, renderer, w, h;
  var mesh, atmosphere, point;

  var overRenderer;
  var running = false, animationFrame = null, resizeObserver = null;
  var earthUniforms, atmosphereUniforms, themeObserver = null, themeMedia = null;
  var keyboardScope = opts.controls || container;

  var curZoomSpeed = 0;
  var zoomSpeed = 50;

  var mouse = { x: 0, y: 0 }, mouseOnDown = { x: 0, y: 0 };
  var rotation = { x: Math.PI*3/2, y: Math.PI / 6.0 },
      target = { x: Math.PI*3/2, y: Math.PI / 6.0 },
      targetOnDown = { x: 0, y: 0 };

  var distance = 855, distanceTarget = 855;
  var padding = 10;
  var PI_HALF = Math.PI / 2;

  // Touch drag/pinch state (added for mobile: the upstream globe is mouse-only).
  var pinchStart = null, pinchDistanceOnStart = distanceTarget;

  function init() {

    container.tabIndex = 0;
    container.setAttribute('role', 'img');
    container.setAttribute('aria-label', 'Peer map. Drag to rotate; pinch, scroll or use the up and down arrow keys to zoom.');

    var shader, uniforms, material;
    w = container.offsetWidth || window.innerWidth;
    h = container.offsetHeight || window.innerHeight;

    camera = new THREE.PerspectiveCamera(30, w / h, 1, 10000);
    camera.position.z = distance;

    scene = new THREE.Scene();

    var geometry = new THREE.SphereGeometry(200, 40, 30);

    shader = Shaders['earth'];
    earthUniforms = uniforms = THREE.UniformsUtils.clone(shader.uniforms);

    uniforms['texture'].value = THREE.ImageUtils.loadTexture(imgDir+'world.jpg');

    material = new THREE.ShaderMaterial({

          uniforms: uniforms,
          vertexShader: shader.vertexShader,
          fragmentShader: shader.fragmentShader

        });

    mesh = new THREE.Mesh(geometry, material);
    mesh.rotation.y = Math.PI;
    scene.add(mesh);

    shader = Shaders['atmosphere'];
    atmosphereUniforms = uniforms = THREE.UniformsUtils.clone(shader.uniforms);

    material = new THREE.ShaderMaterial({

          uniforms: uniforms,
          vertexShader: shader.vertexShader,
          fragmentShader: shader.fragmentShader,
          side: THREE.BackSide,
          depthWrite: false,
          transparent: true

        });

    mesh = new THREE.Mesh(geometry, material);
    mesh.scale.set( 1.1, 1.1, 1.1 );
    scene.add(mesh);

    geometry = new THREE.BoxGeometry(2.75, 2.75, 1);
    geometry.applyMatrix(new THREE.Matrix4().makeTranslation(0,0,-0.5));

    point = new THREE.Mesh(geometry);

    renderer = new THREE.WebGLRenderer({antialias: true, alpha: true});
    renderer.setSize(w, h, false);
    renderer.setClearColor( 0x000000, 0 );

    container.appendChild(renderer.domElement);
    updateTheme();
    if (window.MutationObserver) {
      themeObserver = new MutationObserver(updateTheme);
      themeObserver.observe(document.body, { attributes: true, attributeFilter: ['class'] });
    }
    if (window.matchMedia) {
      themeMedia = window.matchMedia('(prefers-color-scheme: dark)');
      themeMedia.addEventListener('change', updateTheme);
    }

    container.addEventListener('mousedown', onMouseDown, false);
    container.addEventListener('touchstart', onTouchStart, { passive: false });

    if ('onwheel' in document) {
      container.addEventListener('wheel', onMouseWheel, false);
    } else {
      container.addEventListener('mousewheel', onMouseWheel, false);
    }

    document.addEventListener('keydown', onDocumentKeyDown, false);

    window.addEventListener('resize', onWindowResize, false);
    if (window.ResizeObserver) {
      resizeObserver = new ResizeObserver(onWindowResize);
      resizeObserver.observe(container);
    }

    container.addEventListener('mouseover', function() {
      overRenderer = true;
    }, false);

    container.addEventListener('mouseout', function() {
      overRenderer = false;
    }, false);
  }

  function updateTheme() {
    var style = window.getComputedStyle(container);
    earthUniforms.waterScale.value = Number.parseFloat(style.getPropertyValue('--globe-water-scale')) || 28;
    earthUniforms.landColor.value.setStyle(style.getPropertyValue('--globe-land').trim() || '#59636E');
    earthUniforms.waterColor.value.setStyle(style.getPropertyValue('--globe-water').trim() || '#B8C3CE');
    earthUniforms.rimColor.value.setStyle(style.getPropertyValue('--globe-rim').trim() || '#AAB5C0');
    atmosphereUniforms.rimColor.value.copy(earthUniforms.rimColor.value);
  }

  function addData(data, opts) {
    var lat, lng, size, color, i, step, colorFnWrapper;

    opts.animated = opts.animated || false;
    this.is_animated = opts.animated;
    opts.format = opts.format || 'magnitude'; // other option is 'legend'
    if (opts.format === 'magnitude') {
      step = 3;
      colorFnWrapper = function(data, i) { return colorFn(data[i+2]); }
    } else if (opts.format === 'legend') {
      step = 4;
      colorFnWrapper = function(data, i) { return colorFn(data[i+3]); }
    } else if (opts.format === 'peer') {
      colorFnWrapper = function(data, i) { return colorFn(data[i+2]); }
    } else {
      throw('error: format not supported: '+opts.format);
    }

    if (opts.animated) {
      if (this._baseGeometry === undefined) {
        this._baseGeometry = new THREE.Geometry();
        for (i = 0; i < data.length; i += step) {
          lat = data[i];
          lng = data[i + 1];
//        size = data[i + 2];
          color = colorFnWrapper(data,i);
          size = 0;
          addPoint(lat, lng, size, color, this._baseGeometry);
        }
      }
      if(this._morphTargetId === undefined) {
        this._morphTargetId = 0;
      } else {
        this._morphTargetId += 1;
      }
      opts.name = opts.name || 'morphTarget'+this._morphTargetId;
    }
    var subgeo = new THREE.Geometry();
    for (i = 0; i < data.length; i += step) {
      lat = data[i];
      lng = data[i + 1];
      color = colorFnWrapper(data,i);
      size = data[i + 2];
      size = size*200;
      addPoint(lat, lng, size, color, subgeo);
    }
    if (opts.animated) {
      this._baseGeometry.morphTargets.push({'name': opts.name, vertices: subgeo.vertices});
    } else {
      this._baseGeometry = subgeo;
    }

  };

  function createPoints() {
    if (this._baseGeometry !== undefined) {
      if (this.is_animated === false) {
        this.points = new THREE.Mesh(this._baseGeometry, new THREE.MeshBasicMaterial({
              color: 0xffffff,
              vertexColors: THREE.FaceColors,
              morphTargets: false
            }));
      } else {
        if (this._baseGeometry.morphTargets.length < 8) {
          console.log('t l',this._baseGeometry.morphTargets.length);
          var padding = 8-this._baseGeometry.morphTargets.length;
          console.log('padding', padding);
          for(var i=0; i<=padding; i++) {
            console.log('padding',i);
            this._baseGeometry.morphTargets.push({'name': 'morphPadding'+i, vertices: this._baseGeometry.vertices});
          }
        }
        this.points = new THREE.Mesh(this._baseGeometry, new THREE.MeshBasicMaterial({
              color: 0xffffff,
              vertexColors: THREE.FaceColors,
              morphTargets: true
            }));
      }
      scene.add(this.points);
    }
  }

  function addPoint(lat, lng, size, color, subgeo) {

    var phi = (90 - lat) * Math.PI / 180;
    var theta = (180 - lng) * Math.PI / 180;

    point.position.x = 200 * Math.sin(phi) * Math.cos(theta);
    point.position.y = 200 * Math.cos(phi);
    point.position.z = 200 * Math.sin(phi) * Math.sin(theta);

    point.lookAt(mesh.position);

    point.scale.z = Math.max( size, 0.1 ); // avoid non-invertible matrix
    point.updateMatrix();

    for (var i = 0; i < point.geometry.faces.length; i++) {

      point.geometry.faces[i].color = color;

    }
    if(point.matrixAutoUpdate){
      point.updateMatrix();
    }
    subgeo.merge(point.geometry, point.matrix);
  }

  function onMouseDown(event) {
    event.preventDefault();
    container.focus({preventScroll: true});

    container.addEventListener('mousemove', onMouseMove, false);
    container.addEventListener('mouseup', onMouseUp, false);
    container.addEventListener('mouseout', onMouseOut, false);

    mouseOnDown.x = - event.clientX;
    mouseOnDown.y = event.clientY;

    targetOnDown.x = target.x;
    targetOnDown.y = target.y;

    container.style.cursor = 'move';
  }

  function onMouseMove(event) {
    mouse.x = - event.clientX;
    mouse.y = event.clientY;

    var zoomDamp = distance/1000;

    target.x = targetOnDown.x + (mouse.x - mouseOnDown.x) * 0.005 * zoomDamp;
    target.y = targetOnDown.y + (mouse.y - mouseOnDown.y) * 0.005 * zoomDamp;

    target.y = target.y > PI_HALF ? PI_HALF : target.y;
    target.y = target.y < - PI_HALF ? - PI_HALF : target.y;
  }

  function onMouseUp(event) {
    container.removeEventListener('mousemove', onMouseMove, false);
    container.removeEventListener('mouseup', onMouseUp, false);
    container.removeEventListener('mouseout', onMouseOut, false);
    container.style.cursor = 'auto';
  }

  function onMouseOut(event) {
    container.removeEventListener('mousemove', onMouseMove, false);
    container.removeEventListener('mouseup', onMouseUp, false);
    container.removeEventListener('mouseout', onMouseOut, false);
  }

  function touchSpread(event) {
    var dx = event.touches[0].clientX - event.touches[1].clientX;
    var dy = event.touches[0].clientY - event.touches[1].clientY;
    return Math.sqrt(dx * dx + dy * dy);
  }

  function onTouchStart(event) {
    if (event.touches.length === 1) {
      event.preventDefault();
      overRenderer = true;
      pinchStart = null;
      container.addEventListener('touchmove', onTouchMove, { passive: false });
      container.addEventListener('touchend', onTouchEnd, false);
      container.addEventListener('touchcancel', onTouchEnd, false);
      mouseOnDown.x = - event.touches[0].clientX;
      mouseOnDown.y = event.touches[0].clientY;
      targetOnDown.x = target.x;
      targetOnDown.y = target.y;
    } else if (event.touches.length === 2) {
      event.preventDefault();
      pinchStart = touchSpread(event);
      pinchDistanceOnStart = distanceTarget;
      container.addEventListener('touchmove', onTouchMove, { passive: false });
      container.addEventListener('touchend', onTouchEnd, false);
      container.addEventListener('touchcancel', onTouchEnd, false);
    }
  }

  function onTouchMove(event) {
    if (event.touches.length >= 2 && pinchStart != null) {
      event.preventDefault();
      var spread = touchSpread(event);
      distanceTarget = pinchDistanceOnStart - (spread - pinchStart) * 2;
      distanceTarget = distanceTarget > 855 ? 855 : distanceTarget;
      distanceTarget = distanceTarget < 350 ? 350 : distanceTarget;
    } else if (event.touches.length === 1 && pinchStart == null) {
      event.preventDefault();
      mouse.x = - event.touches[0].clientX;
      mouse.y = event.touches[0].clientY;

      var zoomDamp = distance / 1000;

      target.x = targetOnDown.x + (mouse.x - mouseOnDown.x) * 0.005 * zoomDamp;
      target.y = targetOnDown.y + (mouse.y - mouseOnDown.y) * 0.005 * zoomDamp;

      target.y = target.y > PI_HALF ? PI_HALF : target.y;
      target.y = target.y < - PI_HALF ? - PI_HALF : target.y;
    }
  }

  function onTouchEnd(event) {
    if (event.touches.length === 0) {
      container.removeEventListener('touchmove', onTouchMove, { passive: false });
      container.removeEventListener('touchend', onTouchEnd, false);
      container.removeEventListener('touchcancel', onTouchEnd, false);
      pinchStart = null;
    } else if (event.touches.length === 1) {
      // Second finger lifted mid-pinch: resume single-finger rotation cleanly.
      pinchStart = null;
      mouseOnDown.x = - event.touches[0].clientX;
      mouseOnDown.y = event.touches[0].clientY;
      targetOnDown.x = target.x;
      targetOnDown.y = target.y;
    }
  }

  function onMouseWheel(event) {
    if (!running || !container.offsetWidth || !container.offsetHeight) return false;
    event.preventDefault();
    if (overRenderer) {
      if (event.deltaY) {
        zoom(-event.deltaY * (event.deltaMode == 0 ? 1 : 50));
      } else {
        zoom(event.wheelDeltaY * 0.3);
      }
    }
    return false;
  }

  function onDocumentKeyDown(event) {
    if (!running || !keyboardScope.contains(document.activeElement)) return;
    switch (event.keyCode) {
      case 38:
        zoom(100);
        event.preventDefault();
        break;
      case 40:
        zoom(-100);
        event.preventDefault();
        break;
    }
  }

  function onWindowResize( event ) {
    if (!container.offsetWidth || !container.offsetHeight) return;
    camera.aspect = container.offsetWidth / container.offsetHeight;
    camera.updateProjectionMatrix();
    renderer.setSize( container.offsetWidth, container.offsetHeight, false );
  }

  function zoom(delta) {
    distanceTarget -= delta;
    distanceTarget = distanceTarget > 855 ? 855 : distanceTarget;
    distanceTarget = distanceTarget < 350 ? 350 : distanceTarget;
  }

  function animate() {
    if (!running) return;
    animationFrame = requestAnimationFrame(animate);
    render();
  }

  function resume() {
    if (running) return;
    running = true;
    onWindowResize();
    animate();
  }

  function pause() {
    running = false;
    if (animationFrame !== null) cancelAnimationFrame(animationFrame);
    animationFrame = null;
    onMouseUp();
  }

  function reset() {
    target.x = Math.PI * 3 / 2;
    target.y = Math.PI / 6;
    distanceTarget = 855;
  }

  function render() {
    zoom(curZoomSpeed);

    rotation.x += (target.x - rotation.x) * 0.1;
    rotation.y += (target.y - rotation.y) * 0.1;
    distance += (distanceTarget - distance) * 0.3;

    camera.position.x = distance * Math.sin(rotation.x) * Math.cos(rotation.y);
    camera.position.y = distance * Math.sin(rotation.y);
    camera.position.z = distance * Math.cos(rotation.x) * Math.cos(rotation.y);

    camera.lookAt(mesh.position);

    renderer.render(scene, camera);
  }

  function unload() {
    pause();
    if (resizeObserver) resizeObserver.disconnect();
    if (themeObserver) themeObserver.disconnect();
    if (themeMedia) themeMedia.removeEventListener('change', updateTheme);
    container.removeEventListener('mousedown', onMouseDown, false);
    container.removeEventListener('touchstart', onTouchStart, { passive: false });
    container.removeEventListener('touchmove', onTouchMove, { passive: false });
    container.removeEventListener('touchend', onTouchEnd, false);
    container.removeEventListener('touchcancel', onTouchEnd, false);
    if ('onwheel' in document) {
      container.removeEventListener('wheel', onMouseWheel, false);
    } else {
      container.removeEventListener('mousewheel', onMouseWheel, false);
    }
    document.removeEventListener('keydown', onDocumentKeyDown, false);
    window.removeEventListener('resize', onWindowResize, false);
    scene.traverse(function(object) {
      if (object.geometry) object.geometry.dispose();
      if (object.material) {
        object.material.uniforms?.texture?.value?.dispose();
        object.material.dispose();
      }
    });
    if (renderer.dispose) renderer.dispose();
    if (renderer.domElement.parentNode === container) renderer.domElement.remove();

  }

  init();
  this.animate = resume;
  this.resume = resume;
  this.pause = pause;
  this.resize = onWindowResize;
  this.zoom = zoom;
  this.reset = reset;
  this.unload = unload;


  this.__defineGetter__('time', function() {
    return this._time || 0;
  });

  this.__defineSetter__('time', function(t) {
    var validMorphs = [];
    var morphDict = this.points.morphTargetDictionary;
    for(var k in morphDict) {
      if(k.indexOf('morphPadding') < 0) {
        validMorphs.push(morphDict[k]);
      }
    }
    validMorphs.sort();
    var l = validMorphs.length-1;
    var scaledt = t*l+1;
    var index = Math.floor(scaledt);
    for (i=0;i<validMorphs.length;i++) {
      this.points.morphTargetInfluences[validMorphs[i]] = 0;
    }
    var lastIndex = index - 1;
    var leftover = scaledt - index;
    if (lastIndex >= 0) {
      this.points.morphTargetInfluences[lastIndex] = 1 - leftover;
    }
    this.points.morphTargetInfluences[index] = leftover;
    this._time = t;
  });

  this.addData = addData;
  this.createPoints = createPoints;
  this.renderer = renderer;
  this.scene = scene;

  return this;

};
