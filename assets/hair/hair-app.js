/* Hair Day — state, the day picker and the main views */
(function (global) {
  "use strict";
  const D = global.HairData;
  const D2 = global.HairDraw;
  const KEY = "hairday.v1";

  const DEFAULT_STATE = {
    lang: (navigator.language || "en").toLowerCase().indexOf("pt") === 0 ? "pt" : "en",
    theme: "light",
    profile: {
      name: "",
      hairLength: "long",
      hairTexture: "wavy",
      hairColor: "chestnut",
      skinTone: "light",
      hemisphere: "south",
      birthday: "",
      customDays: []
    },
    favourites: [],
    saved: [],
    useMine: true,
    progress: {},
    best: { copycat: 0, memory: 0 }
  };

  let state = load();

  function load() {
    try {
      const raw = JSON.parse(localStorage.getItem(KEY) || "{}");
      const s = Object.assign({}, DEFAULT_STATE, raw);
      s.profile = Object.assign({}, DEFAULT_STATE.profile, raw.profile || {});
      s.best = Object.assign({}, DEFAULT_STATE.best, raw.best || {});
      return s;
    } catch (e) {
      return JSON.parse(JSON.stringify(DEFAULT_STATE));
    }
  }
  function save() {
    try { localStorage.setItem(KEY, JSON.stringify(state)); } catch (e) { /* private mode */ }
  }

  /* ------------------------------------------------------------ language */
  function L(obj) {
    if (!obj) return "";
    return obj[state.lang] || obj.en || "";
  }
  function t(key) { return L(D.UI[key]); }

  /* --------------------------------------------------------------- styles */
  function customStyle(entry) {
    return {
      id: entry.id,
      n: { en: entry.name, pt: entry.name },
      look: entry.look,
      d: 2,
      min: 8,
      tags: entry.tags && entry.tags.length ? entry.tags : ["everyday", "play", "party"],
      len: ["short", "medium", "long"],
      tex: ["straight", "wavy", "curly", "coily"],
      tools: ["brush", "elastic", "clips"],
      custom: true,
      steps: describeLook(entry.look),
      tip: ["You invented this one — you are the expert!", "Você inventou este — a especialista é você!"]
    };
  }

  function describeLook(look) {
    const o = D.OPT_LABELS;
    const steps = [];
    steps.push(["Brush the hair out completely first.", "Escove bem todo o cabelo primeiro."]);
    if (look.texture === "curly" || look.texture === "coily") {
      steps.push(["Damp hair and a little curl cream, scrunched in.", "Cabelo úmido com um pouco de creme, amassando."]);
    }
    if (look.braid && look.braid !== "none") {
      steps.push([
        "Make the braids: " + o.braid[look.braid].en.toLowerCase() + ".",
        "Faça as tranças: " + o.braid[look.braid].pt.toLowerCase() + "."
      ]);
    }
    if (look.updo && look.updo !== "none") {
      steps.push([
        "Tie the hair up: " + o.updo[look.updo].en.toLowerCase() + ".",
        "Prenda o cabelo: " + o.updo[look.updo].pt.toLowerCase() + "."
      ]);
    }
    if (look.bangs && look.bangs !== "none") {
      steps.push([
        "Comb the fringe " + o.bangs[look.bangs].en.toLowerCase() + ".",
        "Penteie a franja " + o.bangs[look.bangs].pt.toLowerCase() + "."
      ]);
    }
    if (look.accessory && look.accessory !== "none") {
      steps.push([
        "Finish with the " + o.accessory[look.accessory].en.toLowerCase() + ".",
        "Termine com " + o.accessory[look.accessory].pt.toLowerCase() + "."
      ]);
    }
    steps.push(["Check it in the mirror and give it a little fluff.", "Confira no espelho e dê uma afofada."]);
    return steps;
  }

  function allStyles() {
    const mine = (state.saved || []).map(customStyle);
    return D.STYLES.concat(mine);
  }
  function styleById(id) {
    if (D.STYLE_BY_ID[id]) return D.STYLE_BY_ID[id];
    const e = (state.saved || []).filter(function (s) { return s.id === id; })[0];
    return e ? customStyle(e) : null;
  }

  function poolFor(profile) {
    const mine = state.useMine ? (state.saved || []).map(customStyle) : [];
    const all = D.STYLES.concat(mine);
    const fit = all.filter(function (s) {
      return s.len.indexOf(profile.hairLength) >= 0 && s.tex.indexOf(profile.hairTexture) >= 0;
    });
    return fit.length >= 5 ? fit : all;
  }

  /* ----------------------------------------------------------- the picker */
  const planCache = {};
  function profileKey(p) {
    return [p.hairLength, p.hairTexture, p.hemisphere, p.birthday,
      (p.customDays || []).map(function (c) { return c.md; }).join(","),
      state.useMine ? (state.saved || []).length : 0].join("~");
  }

  function scoreFor(style, wanted) {
    let sc = 0;
    wanted.forEach(function (tag, i) {
      if (style.tags.indexOf(tag) >= 0) sc += 10 - i;
    });
    return sc;
  }

  function shuffled(list, seed) {
    const r = D2.rng(seed);
    const a = list.slice();
    for (let i = a.length - 1; i > 0; i--) {
      const j = Math.floor(r() * (i + 1));
      const tmp = a[i]; a[i] = a[j]; a[j] = tmp;
    }
    return a;
  }

  function planYear(year) {
    const p = state.profile;
    const ck = year + "|" + profileKey(p);
    if (planCache[ck]) return planCache[ck];

    const specials = D.specialDaysFor(year, p);
    const pool = poolFor(p);
    const plan = {};
    const recent = [];
    const d0 = new Date(Date.UTC(year, 0, 1));
    const days = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0 ? 366 : 365;

    for (let i = 0; i < days; i++) {
      const date = D.addDays(d0, i);
      const key = D.iso(date);
      const sp = specials[key];
      const season = D.seasonOf(date, p.hemisphere);
      const dow = D.WEEKDAY_MOOD[date.getUTCDay()];
      let cands = [];
      let reason;

      if (sp) {
        if (sp.styles && sp.styles.length) {
          cands = pool.filter(function (s) { return sp.styles.indexOf(s.id) >= 0; });
          if (!cands.length) cands = D.STYLES.filter(function (s) { return sp.styles.indexOf(s.id) >= 0; });
        }
        if (!cands.length) {
          cands = pool.filter(function (s) { return scoreFor(s, sp.tags) > 0; });
        }
        reason = { kind: "special", special: sp };
      }
      if (!cands.length) {
        const wanted = dow.tags.concat(D.SEASON_INFO[season].tags);
        const scored = pool.map(function (s) { return { s: s, sc: scoreFor(s, wanted) }; })
          .filter(function (x) { return x.sc > 0; })
          .sort(function (a, b) { return b.sc - a.sc; });
        const top = scored.slice(0, Math.max(6, Math.ceil(scored.length * 0.6)));
        cands = top.map(function (x) { return x.s; });
        if (!cands.length) cands = pool;
        reason = reason || { kind: "day", season: season, dow: dow };
      }

      const order = shuffled(cands, key + "|" + profileKey(p));
      let chosen = null;
      for (let k = 0; k < order.length; k++) {
        if (recent.indexOf(order[k].id) < 0) { chosen = order[k]; break; }
      }
      if (!chosen) chosen = order[0];
      recent.push(chosen.id);
      if (recent.length > 12) recent.shift();

      plan[key] = { id: chosen.id, reason: reason, season: season, special: sp || null };
    }
    planCache[ck] = plan;
    return plan;
  }

  function planFor(date) {
    const plan = planYear(date.getUTCFullYear());
    return plan[D.iso(date)];
  }

  function reasonText(entry, date) {
    if (!entry) return "";
    if (entry.reason.kind === "special") {
      const sp = entry.reason.special;
      return sp.emoji + " " + L(sp.n);
    }
    const si = D.SEASON_INFO[entry.season];
    const dow = D.WEEKDAY_MOOD[date.getUTCDay()];
    return si.emoji + " " + L(dow) + " · " + L(si);
  }

  /* ---------------------------------------------------------------- utils */
  function todayUTC() {
    const n = new Date();
    return new Date(Date.UTC(n.getFullYear(), n.getMonth(), n.getDate()));
  }
  function parseISO(s) {
    const p = s.split("-");
    return new Date(Date.UTC(+p[0], +p[1] - 1, +p[2]));
  }
  function longDate(date) {
    return date.toLocaleDateString(state.lang === "pt" ? "pt-BR" : "en-GB",
      { weekday: "long", day: "numeric", month: "long", year: "numeric", timeZone: "UTC" });
  }
  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function el(id) { return document.getElementById(id); }

  let toastTimer;
  function toast(msg) {
    const n = el("toast");
    n.textContent = msg;
    n.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { n.classList.remove("show"); }, 1900);
  }
  function confetti() {
    const box = document.createElement("div");
    box.className = "confetti";
    const cols = ["#ff4f9a", "#ffc83d", "#8b5cf6", "#2dd4bf", "#38bdf8"];
    for (let i = 0; i < 60; i++) {
      const c = document.createElement("i");
      c.style.left = Math.random() * 100 + "%";
      c.style.background = cols[i % cols.length];
      c.style.animationDuration = 1.6 + Math.random() * 1.6 + "s";
      c.style.animationDelay = Math.random() * 0.5 + "s";
      box.appendChild(c);
    }
    document.body.appendChild(box);
    setTimeout(function () { box.remove(); }, 3600);
  }

  function portrait(style, opts) {
    const look = D2.lookFor(style, state.profile);
    return D2.render(look, Object.assign({ label: L(style.n) }, opts || {}));
  }
  function diffLabel(d) { return [t("easy"), t("easy"), t("medium"), t("tricky")][d] || t("medium"); }

  /* ---------------------------------------------------------------- views */
  const view = function () { return el("view"); };

  function go(hash) { location.hash = hash; }

  function renderMenu() {
    const cards = [
      ["today", "🎀", "menuToday", "menuTodayD", "var(--pink-soft)"],
      ["year", "📅", "menuYear", "menuYearD", "var(--grape-soft)"],
      ["how", "📖", "menuHow", "menuHowD", "#d6f5ee"],
      ["salon", "💇", "menuSalon", "menuSalonD", "#ffe9c9"],
      ["game", "⏱️", "menuGame", "menuGameD", "#ffd7e8"],
      ["memory", "🃏", "menuMemory", "menuMemoryD", "#d9e8ff"],
      ["book", "💖", "menuBook", "menuBookD", "#ffe3f3"],
      ["settings", "⚙️", "menuSettings", "menuSettingsD", "#e8e3f7"]
    ];
    const name = state.profile.name ? esc(state.profile.name) : "";
    const hello = name
      ? (state.lang === "pt" ? "Oi, " + name + "!" : "Hi " + name + "!")
      : t("appName");
    view().innerHTML =
      '<div class="hero"><h1>' + hello + "</h1><p>" + t("tagline") + "</p></div>" +
      '<div class="menu-grid">' +
      cards.map(function (c) {
        return '<button class="menu-card" style="--tint:' + c[4] + '" data-go="#/' + c[0] + '">' +
          '<span class="emoji">' + c[1] + "</span><h3>" + t(c[2]) + "</h3><p>" + t(c[3]) + "</p></button>";
      }).join("") +
      "</div>";
  }

  function head(title, extra) {
    return '<div class="page-head"><button class="back-btn" data-go="#/">←</button>' +
      "<h2>" + title + "</h2>" + (extra || "") + "</div>";
  }

  /* --------------------------------------------------------- today's view */
  function renderToday(isoDate) {
    const date = isoDate ? parseISO(isoDate) : todayUTC();
    const key = D.iso(date);
    const entry = planFor(date);
    const style = styleById(entry.id) || D.STYLES[0];
    const today = D.iso(todayUTC());
    const fav = state.favourites.indexOf(style.id) >= 0;

    let label = longDate(date);
    if (key === today) label = t("today") + " · " + label;
    else if (key === D.iso(D.addDays(todayUTC(), 1))) label = t("tomorrow") + " · " + label;
    else if (key === D.iso(D.addDays(todayUTC(), -1))) label = t("yesterday") + " · " + label;

    const strip = [];
    for (let i = -2; i <= 4; i++) {
      const d = D.addDays(date, i);
      const e = planFor(d);
      const st = styleById(e.id);
      if (!st) continue;
      strip.push('<button class="strip-day' + (i === 0 ? " on" : "") + '" data-date="' + D.iso(d) + '">' +
        "<b>" + d.toLocaleDateString(state.lang === "pt" ? "pt-BR" : "en-GB",
          { weekday: "short", day: "numeric", timeZone: "UTC" }) + "</b>" +
        portrait(st) + "<small>" + esc(L(st.n)) + "</small></button>");
    }

    view().innerHTML =
      head(t("menuToday")) +
      '<div class="card"><div class="today-wrap">' +
        '<div class="portrait">' + portrait(style, { mood: "wow" }) + "</div>" +
        "<div>" +
          '<div class="btn-row" style="margin-bottom:10px">' +
            '<button class="chip" data-step="-1">‹</button>' +
            '<input type="date" id="dpick" value="' + key + '" style="border:2px solid var(--line);border-radius:999px;padding:7px 12px;background:var(--card);color:var(--ink);font-family:inherit;font-weight:700">' +
            '<button class="chip" data-step="1">›</button>' +
          "</div>" +
          '<p class="muted" style="margin:0 0 10px">' + esc(label) + "</p>" +
          '<span class="reason-badge">' + esc(reasonText(entry, date)) + "</span>" +
          '<h3 class="style-name">' + esc(L(style.n)) + "</h3>" +
          '<div class="facts">' +
            '<span class="fact">⏱️ ' + style.min + " " + t("minutes") + "</span>" +
            '<span class="fact">💪 ' + diffLabel(style.d) + "</span>" +
            (style.helper ? '<span class="fact">🧑‍🦰 ' + L(D.TOOLS.helper) + "</span>" : "") +
            (style.custom ? '<span class="fact">✨ ' + (state.lang === "pt" ? "seu penteado" : "your style") + "</span>" : "") +
          "</div>" +
          '<div class="btn-row">' +
            '<button class="btn primary" data-go="#/how/' + style.id + '">' + t("howToDoThis") + "</button>" +
            '<button class="btn" id="favbtn">' + (fav ? "💖 " + t("favourited") : "🤍 " + t("favourite")) + "</button>" +
            '<button class="btn ghost" id="surprise">🎲 ' + t("surprise") + "</button>" +
          "</div>" +
        "</div>" +
      "</div></div>" +
      '<div class="card"><h3 style="margin-top:0">' + t("thisWeek") + '</h3><div class="strip">' + strip.join("") + "</div></div>";

    el("dpick").addEventListener("change", function (e) {
      if (e.target.value) go("#/today/" + e.target.value);
    });
    Array.prototype.forEach.call(document.querySelectorAll("[data-step]"), function (b) {
      b.addEventListener("click", function () {
        go("#/today/" + D.iso(D.addDays(date, +b.dataset.step)));
      });
    });
    Array.prototype.forEach.call(document.querySelectorAll("[data-date]"), function (b) {
      b.addEventListener("click", function () { go("#/today/" + b.dataset.date); });
    });
    el("favbtn").addEventListener("click", function () {
      const i = state.favourites.indexOf(style.id);
      if (i >= 0) state.favourites.splice(i, 1);
      else { state.favourites.push(style.id); confetti(); }
      save();
      renderToday(isoDate);
    });
    el("surprise").addEventListener("click", function () {
      const pool = poolFor(state.profile);
      const pick = pool[Math.floor(Math.random() * pool.length)];
      const box = el("view").querySelector(".portrait");
      box.innerHTML = portrait(pick, { mood: "wow" });
      box.parentNode.querySelector(".style-name").textContent = L(pick.n);
      box.parentNode.querySelector(".reason-badge").textContent = "🎲 " +
        (state.lang === "pt" ? "Surpresa!" : "Surprise!");
      box.parentNode.querySelector('[data-go^="#/how/"]').dataset.go = "#/how/" + pick.id;
      toast("🎲 " + L(pick.n));
    });
  }

  /* ----------------------------------------------------------- year view */
  function renderYear(yearStr) {
    const year = yearStr ? +yearStr : todayUTC().getUTCFullYear();
    const plan = planYear(year);
    const today = D.iso(todayUTC());
    const months = [];
    for (let m = 0; m < 12; m++) {
      const first = new Date(Date.UTC(year, m, 1));
      const daysIn = new Date(Date.UTC(year, m + 1, 0)).getUTCDate();
      let cells = "";
      for (let i = 0; i < first.getUTCDay(); i++) cells += '<span class="day empty"></span>';
      for (let d = 1; d <= daysIn; d++) {
        const key = D.iso(new Date(Date.UTC(year, m, d)));
        const e = plan[key];
        const sp = e && e.special;
        const style = e && styleById(e.id);
        const title = (style ? L(style.n) : "") + (sp ? " — " + L(sp.n) : "");
        cells += '<button class="day' + (sp ? " special" : "") + (key === today ? " today" : "") +
          '" data-date="' + key + '" title="' + esc(title) + '"' +
          (sp ? ' style="background:linear-gradient(135deg,var(--sun),var(--pink-soft))"' : "") +
          ">" + d + (sp ? '<span class="dot">' + sp.emoji + "</span>" : "") + "</button>";
      }
      months.push('<div class="month"><h4>' + D.MONTHS[state.lang][m] + "</h4>" +
        '<div class="dow">' + D.DOW_SHORT[state.lang].map(function (x) { return "<span>" + x + "</span>"; }).join("") + "</div>" +
        '<div class="days">' + cells + "</div></div>");
    }
    view().innerHTML =
      head(t("yearOf") + " " + year,
        '<div class="btn-row" style="margin-left:auto">' +
        '<button class="chip" data-year="' + (year - 1) + '">‹ ' + (year - 1) + "</button>" +
        '<button class="chip" data-year="' + (year + 1) + '">' + (year + 1) + " ›</button></div>") +
      '<div class="legend"><span>✨ ' + t("legendSpecial") + "</span><span>⭕ " + t("legendToday") + "</span>" +
      "<span>👆 " + (state.lang === "pt" ? "toque num dia" : "tap any day") + "</span></div>" +
      '<div class="year-grid">' + months.join("") + "</div>";

    Array.prototype.forEach.call(document.querySelectorAll("[data-year]"), function (b) {
      b.addEventListener("click", function () { go("#/year/" + b.dataset.year); });
    });
    Array.prototype.forEach.call(document.querySelectorAll(".day[data-date]"), function (b) {
      b.addEventListener("click", function () { go("#/today/" + b.dataset.date); });
    });
  }

  /* ---------------------------------------------------------- how-to view */
  function renderHow(id) {
    const list = allStyles();
    const style = (id && styleById(id)) || list[0];
    const doneKey = style.id;
    const done = state.progress[doneKey] || [];

    const tools = (style.tools || []).map(function (k) {
      return '<span class="tool">' + esc(L(D.TOOLS[k] || { en: k, pt: k })) + "</span>";
    }).join("");

    const steps = style.steps.map(function (s, i) {
      return '<li class="' + (done.indexOf(i) >= 0 ? "done" : "") + '" data-step-i="' + i + '">' +
        '<span class="txt">' + esc(state.lang === "pt" ? s[1] : s[0]) + "</span></li>";
    }).join("");

    view().innerHTML =
      head(t("menuHow")) +
      '<div class="howto-layout">' +
        '<div><div class="portrait" style="margin-bottom:14px">' + portrait(style) + "</div>" +
          '<div class="card"><h3 style="margin:0 0 8px">' + t("pickStyle") + "</h3>" +
          '<input id="stsearch" type="text" placeholder="' + t("search") + '" style="width:100%;padding:9px 12px;border-radius:12px;border:2px solid var(--line);background:var(--card-2);color:var(--ink);font-family:inherit;margin-bottom:10px">' +
          '<div class="style-picker" id="stlist"></div></div></div>' +
        "<div>" +
          '<div class="card"><h2 style="margin:0 0 4px">' + esc(L(style.n)) + "</h2>" +
          '<p class="muted" style="margin:0 0 12px">⏱️ ' + style.min + " " + t("minutes") + " · 💪 " + diffLabel(style.d) +
          (style.helper ? " · 🧑‍🦰 " + L(D.TOOLS.helper) : "") + "</p>" +
          "<h4>" + t("youNeed") + '</h4><div class="tools">' + tools + "</div>" +
          "<h4>" + t("steps") + '</h4><ol class="steps" id="steps">' + steps + "</ol>" +
          (style.tip ? '<div class="tip">💡 <b>' + t("tipTitle") + ":</b> " +
            esc(state.lang === "pt" ? style.tip[1] : style.tip[0]) + "</div>" : "") +
          "</div>" +
        "</div>" +
      "</div>";

    function drawList(filter) {
      const f = (filter || "").toLowerCase();
      el("stlist").innerHTML = list.filter(function (s) {
        return !f || L(s.n).toLowerCase().indexOf(f) >= 0;
      }).map(function (s) {
        return '<button class="mini' + (s.id === style.id ? " on" : "") + '" data-style="' + s.id + '">' +
          portrait(s) + "<b>" + esc(L(s.n)) + "</b></button>";
      }).join("") || '<p class="muted">' + t("nothingHere") + "</p>";
      Array.prototype.forEach.call(el("stlist").querySelectorAll("[data-style]"), function (b) {
        b.addEventListener("click", function () { go("#/how/" + b.dataset.style); });
      });
    }
    drawList("");
    el("stsearch").addEventListener("input", function (e) { drawList(e.target.value); });

    Array.prototype.forEach.call(el("steps").children, function (li) {
      li.addEventListener("click", function () {
        const i = +li.dataset.stepI;
        const arr = state.progress[doneKey] || [];
        const at = arr.indexOf(i);
        if (at >= 0) arr.splice(at, 1); else arr.push(i);
        state.progress[doneKey] = arr;
        save();
        li.classList.toggle("done");
        if (arr.length === style.steps.length) { confetti(); toast("🎉 " + t("gDone")); }
      });
    });
  }

  /* -------------------------------------------------------------- lookbook */
  function renderBook() {
    const favs = state.favourites.map(styleById).filter(Boolean);
    const mine = (state.saved || []).map(customStyle);
    const grid = function (items, empty) {
      if (!items.length) return '<p class="muted">' + empty + "</p>";
      return '<div class="saved-grid">' + items.map(function (s) {
        return '<div class="saved-item"><button class="mini" data-style="' + s.id + '">' +
          portrait(s) + "<b>" + esc(L(s.n)) + "</b></button>" +
          (s.custom ? '<button class="del" data-del="' + s.id + '">✕</button>' : "") + "</div>";
      }).join("") + "</div>";
    };
    view().innerHTML =
      head(t("menuBook")) +
      '<div class="card"><h3 style="margin-top:0">💖 ' + t("favourited") + "</h3>" +
      grid(favs, t("nothingHere")) + "</div>" +
      '<div class="card"><h3 style="margin-top:0">✨ ' + t("menuSalon") + "</h3>" +
      grid(mine, t("nothingHere")) +
      '<p style="margin-top:14px"><label class="fact" style="cursor:pointer"><input type="checkbox" id="usemine"' +
      (state.useMine ? " checked" : "") + "> " + t("useMine") + "</label></p>" +
      '<div class="btn-row" style="margin-top:10px"><button class="btn primary" data-go="#/salon">💇 ' +
      t("menuSalon") + "</button></div></div>";

    Array.prototype.forEach.call(document.querySelectorAll("[data-style]"), function (b) {
      b.addEventListener("click", function () { go("#/how/" + b.dataset.style); });
    });
    Array.prototype.forEach.call(document.querySelectorAll("[data-del]"), function (b) {
      b.addEventListener("click", function () {
        if (!confirm(t("deleteQ"))) return;
        state.saved = state.saved.filter(function (s) { return s.id !== b.dataset.del; });
        state.favourites = state.favourites.filter(function (f) { return f !== b.dataset.del; });
        save(); clearPlans(); renderBook();
      });
    });
    el("usemine").addEventListener("change", function (e) {
      state.useMine = e.target.checked; save(); clearPlans();
    });
  }

  /* -------------------------------------------------------------- settings */
  function renderSettings() {
    const p = state.profile;
    /* group = the label set in OPT_LABELS, field = the profile field it writes */
    const opt = function (group, field, value, cur) {
      const label = D.OPT_LABELS[group] && D.OPT_LABELS[group][value]
        ? D.OPT_LABELS[group][value] : { en: value, pt: value };
      return '<button class="opt' + (value === cur ? " on" : "") + '" data-set="' + field +
        '" data-val="' + value + '">' + esc(L(label)) + "</button>";
    };
    const colors = Object.keys(D.HAIR_COLORS).map(function (k) {
      const c = D.HAIR_COLORS[k];
      const bg = c.rainbow
        ? "linear-gradient(135deg,#ff6fae,#ffc83d,#2dd4bf,#8b5cf6)" : c.hex;
      return '<button class="swatch' + (k === p.hairColor ? " on" : "") + '" title="' + esc(L(c)) +
        '" style="background:' + bg + '" data-set="hairColor" data-val="' + k + '"></button>';
    }).join("");
    const skins = Object.keys(D.SKIN_TONES).map(function (k) {
      return '<button class="swatch' + (k === p.skinTone ? " on" : "") +
        '" style="background:' + D.SKIN_TONES[k] + '" data-set="skinTone" data-val="' + k + '"></button>';
    }).join("");

    const custom = (p.customDays || []).map(function (c, i) {
      return "<li>" + (c.emoji || "⭐") + " <b>" + esc(c.name) + "</b> — " + c.md +
        '<button data-rm="' + i + '">✕</button></li>';
    }).join("");

    view().innerHTML =
      head(t("menuSettings")) +
      '<div class="card"><div class="today-wrap">' +
        '<div class="portrait">' + D2.render(D2.lookFor(
          { look: { updo: "halfUp", accessory: "bow", accColor: "pink" } }, p), { mood: "wow" }) + "</div>" +
        "<div>" +
          '<div class="field"><label>' + t("yourName") + '</label><input type="text" id="pname" value="' +
            esc(p.name) + '" placeholder="' + (state.lang === "pt" ? "seu nome" : "your name") + '"></div>' +
          '<div class="opt-group"><h4>' + t("hairLength") + '</h4><div class="opts">' +
            ["short", "medium", "long"].map(function (v) {
              return opt("length", "hairLength", v, p.hairLength);
            }).join("") + "</div></div>" +
          '<div class="opt-group"><h4>' + t("hairTexture") + '</h4><div class="opts">' +
            ["straight", "wavy", "curly", "coily"].map(function (v) {
              return opt("texture", "hairTexture", v, p.hairTexture);
            }).join("") + "</div></div>" +
          '<div class="opt-group"><h4>' + t("hairColor") + '</h4><div class="opts">' + colors + "</div></div>" +
          '<div class="opt-group"><h4>' + t("skinTone") + '</h4><div class="opts">' + skins + "</div></div>" +
        "</div>" +
      "</div></div>" +
      '<div class="card"><div class="row">' +
        '<div class="field"><label>' + t("whereYouLive") + '</label><select id="hemi">' +
          '<option value="south"' + (p.hemisphere === "south" ? " selected" : "") + ">" + t("south") + "</option>" +
          '<option value="north"' + (p.hemisphere === "north" ? " selected" : "") + ">" + t("north") + "</option>" +
        "</select></div>" +
        '<div class="field"><label>' + t("birthday") + '</label><input type="date" id="bday" value="' +
          (p.birthday ? "2000-" + p.birthday : "") + '"></div>' +
      "</div>" +
      "<h3>" + t("myDays") + '</h3><p class="muted">' + t("myDaysHint") + "</p>" +
      '<div class="row"><input type="text" id="cdname" placeholder="' + t("dayName") + '">' +
      '<input type="date" id="cddate"><button class="btn primary" id="addday">' + t("addDay") + "</button></div>" +
      '<ul class="custom-day-list">' + custom + "</ul></div>" +
      '<div class="card center"><button class="btn ghost" id="wipe">🧹 ' + t("resetAll") + "</button></div>";

    Array.prototype.forEach.call(document.querySelectorAll("[data-set]"), function (b) {
      b.addEventListener("click", function () {
        p[b.dataset.set] = b.dataset.val;
        save(); clearPlans(); renderSettings();
      });
    });
    el("pname").addEventListener("input", function (e) { p.name = e.target.value; save(); });
    el("hemi").addEventListener("change", function (e) { p.hemisphere = e.target.value; save(); clearPlans(); });
    el("bday").addEventListener("change", function (e) {
      p.birthday = e.target.value ? e.target.value.slice(5) : "";
      save(); clearPlans(); renderSettings();
    });
    el("addday").addEventListener("click", function () {
      const name = el("cdname").value.trim();
      const date = el("cddate").value;
      if (!name || !date) { toast("🤔 " + t("dayName")); return; }
      p.customDays = p.customDays || [];
      p.customDays.push({ name: name, md: date.slice(5), emoji: "⭐" });
      save(); clearPlans(); renderSettings(); toast("⭐ " + name);
    });
    Array.prototype.forEach.call(document.querySelectorAll("[data-rm]"), function (b) {
      b.addEventListener("click", function () {
        p.customDays.splice(+b.dataset.rm, 1);
        save(); clearPlans(); renderSettings();
      });
    });
    el("wipe").addEventListener("click", function () {
      if (!confirm(t("resetQ"))) return;
      state = JSON.parse(JSON.stringify(DEFAULT_STATE));
      save(); clearPlans(); applyTheme(); go("#/");
    });
  }

  function clearPlans() { Object.keys(planCache).forEach(function (k) { delete planCache[k]; }); }

  /* ----------------------------------------------------------------- shell */
  function applyTheme() {
    document.documentElement.setAttribute("data-theme", state.theme);
    document.documentElement.setAttribute("lang", state.lang === "pt" ? "pt-BR" : "en");
    const lb = el("langbtn"), tb = el("themebtn");
    if (lb) lb.textContent = state.lang === "pt" ? "🇧🇷 PT" : "🇬🇧 EN";
    if (tb) tb.textContent = state.theme === "dark" ? "🌙" : "☀️";
  }

  function route() {
    const h = (location.hash || "#/").replace(/^#\/?/, "");
    const parts = h.split("/");
    window.scrollTo(0, 0);
    switch (parts[0]) {
      case "today": renderToday(parts[1]); break;
      case "year": renderYear(parts[1]); break;
      case "how": renderHow(parts[1]); break;
      case "book": renderBook(); break;
      case "settings": renderSettings(); break;
      case "salon": global.HairGames.salon(view()); break;
      case "game": global.HairGames.copycat(view()); break;
      case "memory": global.HairGames.memory(view()); break;
      default: renderMenu();
    }
  }

  function start() {
    applyTheme();
    document.body.addEventListener("click", function (e) {
      const b = e.target.closest ? e.target.closest("[data-go]") : null;
      if (b) go(b.dataset.go);
    });
    el("langbtn").addEventListener("click", function () {
      state.lang = state.lang === "pt" ? "en" : "pt";
      save(); applyTheme(); route();
    });
    el("themebtn").addEventListener("click", function () {
      state.theme = state.theme === "dark" ? "light" : "dark";
      save(); applyTheme();
    });
    window.addEventListener("hashchange", route);
    route();
  }

  global.HairApp = {
    start: start, route: route, go: go, t: t, L: L, esc: esc,
    portrait: portrait, toast: toast, confetti: confetti, save: save,
    clearPlans: clearPlans, styleById: styleById, allStyles: allStyles,
    planYear: planYear, planFor: planFor,
    get state() { return state; }
  };
})(window);
