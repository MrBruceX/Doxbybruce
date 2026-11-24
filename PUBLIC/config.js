// config.js — MAX SHOP configuration  |  client-side only, no backend
'use strict';
const CONFIG = (() => {
  const LOGO_PATH   = 'assets/logo.png';
  const SHOP_NAME   = 'MAX SHOP';
  const FOOTER_TEXT = 'MAX SHOP © 2025 — Account Generator';

  const SERVICE_LOGOS = {
    discord:       'assets/services/discord.png',
    steam:         'assets/services/steam.png',
    rockstar:      'assets/services/rockstar.png',
    rockstar_code: 'assets/services/rockstar.png',
  };

  const DAILY_LIMIT = 40;
  const MAX_PER_GEN = 10;

  function applyLogos(){
    document.querySelectorAll('.nav-brand-icon img,.brand-icon img').forEach(img=>{
      img.src=LOGO_PATH;
      img.onerror=function(){this.style.display='none';if(!this.parentNode.dataset.fbSet){this.parentNode.dataset.fbSet='1';this.parentNode.insertAdjacentText('beforeend','⚡');}};
    });
    document.querySelectorAll('.nav-brand').forEach(el=>{
      if(el.dataset.logoInjected) return; el.dataset.logoInjected='1';
      const img=document.createElement('img');img.src=LOGO_PATH;img.alt=SHOP_NAME;img.style.cssText='width:22px;height:22px;object-fit:contain;filter:unset;vertical-align:middle;margin-right:4px';
      img.onerror=function(){this.remove();};el.prepend(img);
    });
    const foot=document.querySelector('footer');
    if(foot && FOOTER_TEXT) foot.textContent=FOOTER_TEXT;
  }

  if(document.readyState==='loading'){document.addEventListener('DOMContentLoaded',applyLogos);}else{applyLogos();}

  return { LOGO_PATH, SHOP_NAME, FOOTER_TEXT, SERVICE_LOGOS, DAILY_LIMIT, MAX_PER_GEN };
})();