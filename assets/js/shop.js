// Demo storefront: catalog, cart, checkout, reviews and marketing tools.
// All state lives in localStorage; no data leaves the browser.
(function () {
  "use strict";

  const STORAGE_KEY = "idnteq-shop-v1";

  const SEED = {
    products: [
      { id: "p1", name: "Wireless Headphones", category: "Electronics", price: 89.99, icon: "🎧", color: "#2b6cb0", featured: true, description: "Over-ear, noise cancelling, 30-hour battery." },
      { id: "p2", name: "Smart Watch", category: "Electronics", price: 149.0, icon: "⌚", color: "#553c9a", featured: false, description: "Heart-rate, GPS and notifications on your wrist." },
      { id: "p3", name: "Coffee Grinder", category: "Home", price: 39.5, icon: "☕", color: "#7b341e", featured: true, description: "Burr grinder with 18 grind settings." },
      { id: "p4", name: "Desk Lamp", category: "Home", price: 24.99, icon: "💡", color: "#b7791f", featured: false, description: "Dimmable LED with USB charging port." },
      { id: "p5", name: "Running Shoes", category: "Sports", price: 74.0, icon: "👟", color: "#276749", featured: false, description: "Lightweight trainers with responsive foam." },
      { id: "p6", name: "Yoga Mat", category: "Sports", price: 29.0, icon: "🧘", color: "#285e61", featured: false, description: "6mm non-slip mat with carry strap." },
      { id: "p7", name: "Backpack", category: "Accessories", price: 54.99, icon: "🎒", color: "#9b2c2c", featured: true, description: "Water-resistant, fits a 16\" laptop." },
      { id: "p8", name: "Sunglasses", category: "Accessories", price: 19.99, icon: "🕶️", color: "#4a5568", featured: false, description: "Polarised lenses with UV400 protection." },
    ],
    reviews: {
      p1: [
        { name: "Sam", rating: 5, text: "Great sound and the battery lasts forever.", date: "2026-08-02", verified: true },
        { name: "Priya", rating: 4, text: "Comfortable, noise cancelling could be stronger.", date: "2026-08-19", verified: false },
      ],
      p3: [{ name: "Jordan", rating: 5, text: "Makes my morning coffee so much better.", date: "2026-07-11", verified: true }],
      p7: [{ name: "Alex", rating: 4, text: "Lots of pockets, holds up well in rain.", date: "2026-09-01", verified: true }],
    },
    cart: {},
    orders: [],
    promos: {
      WELCOME10: { type: "percent", value: 10, uses: 0 },
      SAVE5: { type: "fixed", value: 5, uses: 0 },
    },
    banner: { text: "Welcome! Use code WELCOME10 for 10% off your first order.", on: true },
    subscribers: [],
    views: {},
    appliedPromo: null,
  };

  let state = load();

  function load() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (raw) return Object.assign(structuredClone(SEED), JSON.parse(raw));
    } catch (e) {
      /* storage unavailable or corrupt — fall back to seed data */
    }
    return structuredClone(SEED);
  }

  function save() {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
    } catch (e) {
      /* ignore — the page still works for this visit */
    }
  }

  // ===== Helpers =====
  const $ = (id) => document.getElementById(id);
  const money = (n) => "$" + n.toFixed(2);
  const today = () => new Date().toISOString().slice(0, 10);

  function esc(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
  }

  function product(id) {
    return state.products.find((p) => p.id === id);
  }

  function ratingOf(id) {
    const list = state.reviews[id] || [];
    if (!list.length) return { avg: 0, count: 0 };
    const sum = list.reduce((a, r) => a + r.rating, 0);
    return { avg: sum / list.length, count: list.length };
  }

  function stars(avg) {
    const full = Math.round(avg);
    return '<span class="shop-stars" aria-label="' + avg.toFixed(1) + ' out of 5">' + "★".repeat(full) + "☆".repeat(5 - full) + "</span>";
  }

  function toast(msg) {
    const t = $("toast");
    t.textContent = msg;
    t.hidden = false;
    clearTimeout(toast.timer);
    toast.timer = setTimeout(() => (t.hidden = true), 2200);
  }

  function hasPurchased(id) {
    return state.orders.some((o) => o.items.some((i) => i.id === id));
  }

  // ===== Tabs =====
  document.querySelectorAll(".tab-button").forEach((btn) => {
    btn.addEventListener("click", () => openTab(btn.dataset.tab));
  });

  function openTab(name) {
    document.querySelectorAll(".tab-content").forEach((el) => (el.style.display = el.id === name ? "block" : "none"));
    document.querySelectorAll(".tab-button").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
    render();
  }

  // ===== Store =====
  function renderCategories() {
    const sel = $("categoryFilter");
    const current = sel.value;
    const cats = [...new Set(state.products.map((p) => p.category))].sort();
    sel.innerHTML = '<option value="">All categories</option>' + cats.map((c) => `<option>${esc(c)}</option>`).join("");
    sel.value = current;
  }

  function renderStore() {
    const q = $("searchInput").value.trim().toLowerCase();
    const cat = $("categoryFilter").value;
    const sort = $("sortSelect").value;

    let list = state.products.filter(
      (p) => (!cat || p.category === cat) && (!q || (p.name + " " + p.description).toLowerCase().includes(q))
    );

    const cmp = {
      featured: (a, b) => b.featured - a.featured,
      "price-asc": (a, b) => a.price - b.price,
      "price-desc": (a, b) => b.price - a.price,
      rating: (a, b) => ratingOf(b.id).avg - ratingOf(a.id).avg,
      reviews: (a, b) => ratingOf(b.id).count - ratingOf(a.id).count,
    }[sort];
    list = list.slice().sort(cmp);

    $("productGrid").innerHTML = list.length
      ? list
          .map((p) => {
            const r = ratingOf(p.id);
            return `
        <div class="shop-card">
          <div class="shop-thumb" style="background:${p.color}" data-open="${p.id}">${p.icon}
            ${p.featured ? '<span class="shop-tag">Featured</span>' : ""}
          </div>
          <div class="shop-card-body">
            <h3 data-open="${p.id}">${esc(p.name)}</h3>
            <div class="shop-muted">${esc(p.category)}</div>
            <div>${stars(r.avg)} <span class="shop-muted">(${r.count})</span></div>
            <div class="shop-price">${money(p.price)}</div>
            <div class="shop-row">
              <button class="shop-btn" data-add="${p.id}">Add to cart</button>
              <button class="shop-btn secondary" data-open="${p.id}">Reviews</button>
            </div>
          </div>
        </div>`;
          })
          .join("")
      : '<p class="shop-muted">No products match your search.</p>';
  }

  ["searchInput", "categoryFilter", "sortSelect"].forEach((id) => $(id).addEventListener("input", renderStore));

  $("productGrid").addEventListener("click", (e) => {
    const add = e.target.closest("[data-add]");
    const open = e.target.closest("[data-open]");
    if (add) addToCart(add.dataset.add);
    else if (open) openProduct(open.dataset.open);
  });

  // ===== Product modal & reviews =====
  function openProduct(id) {
    const p = product(id);
    state.views[id] = (state.views[id] || 0) + 1;
    save();
    renderModal(p);
    $("productModal").hidden = false;
  }

  function renderModal(p) {
    const r = ratingOf(p.id);
    const reviews = (state.reviews[p.id] || []).slice().reverse();
    const shareUrl = location.origin + location.pathname + "#" + p.id;
    const shareText = encodeURIComponent("Check out " + p.name + " — " + money(p.price));
    $("modalBody").innerHTML = `
      <div class="shop-detail">
        <div class="shop-thumb large" style="background:${p.color}">${p.icon}</div>
        <div>
          <h2>${esc(p.name)}</h2>
          <p class="shop-muted">${esc(p.category)}</p>
          <p>${esc(p.description)}</p>
          <p>${stars(r.avg)} ${r.count ? r.avg.toFixed(1) + " from " + r.count + " review" + (r.count > 1 ? "s" : "") : "No reviews yet"}</p>
          <p class="shop-price">${money(p.price)}</p>
          <div class="shop-row">
            <button class="shop-btn" data-add="${p.id}">Add to cart</button>
            <a class="shop-btn secondary" target="_blank" rel="noopener" href="https://twitter.com/intent/tweet?text=${shareText}&url=${encodeURIComponent(shareUrl)}">Share on X</a>
            <a class="shop-btn secondary" target="_blank" rel="noopener" href="https://www.facebook.com/sharer/sharer.php?u=${encodeURIComponent(shareUrl)}">Share on Facebook</a>
            <button class="shop-btn secondary" data-copy="${esc(shareUrl)}">Copy link</button>
          </div>
        </div>
      </div>
      <h3>Customer Reviews</h3>
      ${ratingBreakdown(p.id)}
      <form class="shop-form" id="reviewForm">
        <label>Your name <input name="name" type="text" required maxlength="40" /></label>
        <label>Rating
          <select name="rating">
            <option value="5">★★★★★ Excellent</option>
            <option value="4">★★★★☆ Good</option>
            <option value="3">★★★☆☆ Okay</option>
            <option value="2">★★☆☆☆ Poor</option>
            <option value="1">★☆☆☆☆ Terrible</option>
          </select>
        </label>
        <label>Review <textarea name="text" rows="3" required maxlength="500"></textarea></label>
        <button type="submit" class="shop-btn">Post review</button>
      </form>
      <div class="shop-reviews">
        ${
          reviews.length
            ? reviews
                .map(
                  (rv) => `
          <div class="shop-review">
            <div>${stars(rv.rating)} <strong>${esc(rv.name)}</strong>
              ${rv.verified ? '<span class="shop-verified">Verified purchase</span>' : ""}
              <span class="shop-muted">${esc(rv.date)}</span></div>
            <p>${esc(rv.text)}</p>
          </div>`
                )
                .join("")
            : '<p class="shop-muted">Be the first to review this product.</p>'
        }
      </div>`;

    $("reviewForm").addEventListener("submit", (e) => {
      e.preventDefault();
      const f = e.target;
      (state.reviews[p.id] = state.reviews[p.id] || []).push({
        name: f.name.value.trim(),
        rating: Number(f.rating.value),
        text: f.text.value.trim(),
        date: today(),
        verified: hasPurchased(p.id),
      });
      save();
      toast("Thanks for your review!");
      renderModal(p);
      render();
    });
  }

  function ratingBreakdown(id) {
    const list = state.reviews[id] || [];
    if (!list.length) return "";
    return (
      '<div class="shop-breakdown">' +
      [5, 4, 3, 2, 1]
        .map((n) => {
          const c = list.filter((r) => r.rating === n).length;
          const pct = Math.round((c / list.length) * 100);
          return `<div class="shop-bar-row"><span>${n}★</span><div class="shop-bar"><div style="width:${pct}%"></div></div><span>${c}</span></div>`;
        })
        .join("") +
      "</div>"
    );
  }

  $("productModal").addEventListener("click", (e) => {
    if (e.target.id === "productModal" || e.target.closest(".shop-modal-close")) {
      $("productModal").hidden = true;
      return;
    }
    const add = e.target.closest("[data-add]");
    if (add) addToCart(add.dataset.add);
    const copy = e.target.closest("[data-copy]");
    if (copy) {
      navigator.clipboard?.writeText(copy.dataset.copy).then(
        () => toast("Link copied"),
        () => toast(copy.dataset.copy)
      );
    }
  });

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") $("productModal").hidden = true;
  });

  // ===== Cart =====
  function addToCart(id) {
    state.cart[id] = (state.cart[id] || 0) + 1;
    save();
    toast(product(id).name + " added to cart");
    render();
  }

  function cartLines() {
    return Object.entries(state.cart)
      .filter(([id]) => product(id))
      .map(([id, qty]) => ({ ...product(id), qty }));
  }

  function totals() {
    const subtotal = cartLines().reduce((a, l) => a + l.price * l.qty, 0);
    let discount = 0;
    const promo = state.appliedPromo && state.promos[state.appliedPromo];
    if (promo) discount = promo.type === "percent" ? (subtotal * promo.value) / 100 : Math.min(promo.value, subtotal);
    const shipping = subtotal - discount >= 50 || subtotal === 0 ? 0 : 4.99;
    return { subtotal, discount, shipping, total: subtotal - discount + shipping };
  }

  function renderCart() {
    const lines = cartLines();
    const count = lines.reduce((a, l) => a + l.qty, 0);
    $("cartCount").textContent = count;

    if (!lines.length) {
      $("cartItems").innerHTML = '<p class="shop-muted">Your cart is empty.</p>';
      $("cartSummary").innerHTML = "";
      $("checkoutForm").hidden = true;
      return;
    }

    $("cartItems").innerHTML = `
      <table class="shop-table">
        <tr><th></th><th>Product</th><th>Price</th><th>Qty</th><th>Total</th><th></th></tr>
        ${lines
          .map(
            (l) => `
          <tr>
            <td><span class="shop-mini" style="background:${l.color}">${l.icon}</span></td>
            <td>${esc(l.name)}</td>
            <td>${money(l.price)}</td>
            <td><input type="number" min="1" value="${l.qty}" data-qty="${l.id}" class="shop-qty" /></td>
            <td>${money(l.price * l.qty)}</td>
            <td><button class="shop-btn secondary" data-remove="${l.id}">Remove</button></td>
          </tr>`
          )
          .join("")}
      </table>`;

    const t = totals();
    const toFree = 50 - (t.subtotal - t.discount);
    $("cartSummary").innerHTML = `
      <div>Subtotal <span>${money(t.subtotal)}</span></div>
      ${t.discount ? `<div class="shop-good">Discount (${esc(state.appliedPromo)}) <span>−${money(t.discount)}</span></div>` : ""}
      <div>Shipping <span>${t.shipping ? money(t.shipping) : "Free"}</span></div>
      ${toFree > 0 ? `<div class="shop-muted">Add ${money(toFree)} more for free shipping.</div>` : ""}
      <div class="shop-total">Total <span>${money(t.total)}</span></div>
      ${recommendations(lines)}`;
    $("checkoutForm").hidden = false;
    $("promoInput").value = state.appliedPromo || "";
  }

  // "You might also like": popular products from the same categories not already in the cart
  function recommendations(lines) {
    const inCart = new Set(lines.map((l) => l.id));
    const cats = new Set(lines.map((l) => l.category));
    const recs = state.products
      .filter((p) => !inCart.has(p.id))
      .sort((a, b) => cats.has(b.category) - cats.has(a.category) || ratingOf(b.id).avg - ratingOf(a.id).avg)
      .slice(0, 3);
    if (!recs.length) return "";
    return (
      '<h3>You might also like</h3><div class="shop-recs">' +
      recs
        .map((p) => `<button class="shop-rec" data-add="${p.id}"><span class="shop-mini" style="background:${p.color}">${p.icon}</span> ${esc(p.name)} · ${money(p.price)}</button>`)
        .join("") +
      "</div>"
    );
  }

  $("cart").addEventListener("click", (e) => {
    const rm = e.target.closest("[data-remove]");
    const add = e.target.closest("[data-add]");
    if (rm) {
      delete state.cart[rm.dataset.remove];
      save();
      render();
    } else if (add) addToCart(add.dataset.add);
  });

  $("cart").addEventListener("change", (e) => {
    const q = e.target.closest("[data-qty]");
    if (!q) return;
    const n = Math.max(1, parseInt(q.value, 10) || 1);
    state.cart[q.dataset.qty] = n;
    save();
    render();
  });

  $("applyPromo").addEventListener("click", () => {
    const code = $("promoInput").value.trim().toUpperCase();
    if (!code) {
      state.appliedPromo = null;
      $("promoMsg").textContent = "";
    } else if (state.promos[code]) {
      state.appliedPromo = code;
      $("promoMsg").textContent = "Code " + code + " applied.";
    } else {
      state.appliedPromo = null;
      $("promoMsg").textContent = "That code isn't valid.";
    }
    save();
    renderCart();
  });

  $("checkoutForm").addEventListener("submit", (e) => {
    e.preventDefault();
    const t = totals();
    const email = $("custEmail").value.trim();
    const order = {
      id: "ORD-" + Date.now().toString(36).toUpperCase(),
      date: today(),
      name: $("custName").value.trim(),
      email,
      address: $("custAddress").value.trim(),
      items: cartLines().map((l) => ({ id: l.id, name: l.name, price: l.price, qty: l.qty })),
      promo: state.appliedPromo,
      ...t,
    };
    state.orders.push(order);
    if (order.promo && state.promos[order.promo]) state.promos[order.promo].uses++;
    if ($("custOptIn").checked && !state.subscribers.includes(email)) state.subscribers.push(email);
    state.cart = {};
    state.appliedPromo = null;
    save();
    e.target.reset();
    toast("Order " + order.id + " placed — thank you!");
    openTab("orders");
  });

  // ===== Orders =====
  function renderOrders() {
    $("orderList").innerHTML = state.orders.length
      ? state.orders
          .slice()
          .reverse()
          .map(
            (o) => `
        <div class="shop-order">
          <div class="shop-order-head"><strong>${esc(o.id)}</strong> <span class="shop-muted">${esc(o.date)}</span> <span>${money(o.total)}</span></div>
          <ul>
            ${o.items
              .map(
                (i) => `<li>${i.qty} × ${esc(i.name)} — ${money(i.price * i.qty)}
                  <button class="shop-btn secondary small" data-open="${i.id}">Write a review</button></li>`
              )
              .join("")}
          </ul>
          ${o.promo ? `<div class="shop-muted">Promo ${esc(o.promo)} saved ${money(o.discount)}</div>` : ""}
        </div>`
          )
          .join("")
      : '<p class="shop-muted">No orders yet.</p>';
  }

  $("orderList").addEventListener("click", (e) => {
    const open = e.target.closest("[data-open]");
    if (open && product(open.dataset.open)) openProduct(open.dataset.open);
  });

  // ===== Marketing =====
  function renderMarketing() {
    const revenue = state.orders.reduce((a, o) => a + o.total, 0);
    const allReviews = Object.values(state.reviews).flat();
    const avg = allReviews.length ? allReviews.reduce((a, r) => a + r.rating, 0) / allReviews.length : 0;
    const views = Object.values(state.views).reduce((a, v) => a + v, 0);
    const unitsSold = {};
    state.orders.forEach((o) => o.items.forEach((i) => (unitsSold[i.id] = (unitsSold[i.id] || 0) + i.qty)));
    const best = Object.entries(unitsSold).sort((a, b) => b[1] - a[1])[0];

    $("stats").innerHTML = [
      ["Revenue", money(revenue)],
      ["Orders", state.orders.length],
      ["Avg. order", state.orders.length ? money(revenue / state.orders.length) : "—"],
      ["Reviews", allReviews.length],
      ["Avg. rating", avg ? avg.toFixed(2) + " ★" : "—"],
      ["Product views", views],
      ["Subscribers", state.subscribers.length],
      ["Best seller", best && product(best[0]) ? esc(product(best[0]).name) : "—"],
    ]
      .map(([k, v]) => `<div class="shop-stat"><div class="shop-muted">${k}</div><div class="shop-stat-val">${v}</div></div>`)
      .join("");

    $("bannerText").value = state.banner.text;
    $("bannerOn").checked = state.banner.on;

    $("promoTable").innerHTML =
      "<tr><th>Code</th><th>Discount</th><th>Uses</th><th></th></tr>" +
      Object.entries(state.promos)
        .map(
          ([code, p]) => `<tr><td><code>${esc(code)}</code></td>
            <td>${p.type === "percent" ? p.value + "%" : money(p.value)} off</td>
            <td>${p.uses}</td>
            <td><button class="shop-btn secondary small" data-delpromo="${esc(code)}">Delete</button></td></tr>`
        )
        .join("");

    $("featureList").innerHTML = state.products
      .map(
        (p) => `<label class="shop-check"><input type="checkbox" data-feature="${p.id}" ${p.featured ? "checked" : ""} />
          ${p.icon} ${esc(p.name)} <span class="shop-muted">(${state.views[p.id] || 0} views, ${unitsSold[p.id] || 0} sold)</span></label>`
      )
      .join("");

    $("subList").innerHTML = state.subscribers.length
      ? state.subscribers.map((s) => `<li>${esc(s)} <button class="shop-btn secondary small" data-unsub="${esc(s)}">Remove</button></li>`).join("")
      : '<li class="shop-muted">No subscribers yet.</li>';
  }

  function renderBanner() {
    const b = $("promoBanner");
    b.hidden = !(state.banner.on && state.banner.text);
    b.textContent = state.banner.text;
  }

  $("bannerForm").addEventListener("submit", (e) => {
    e.preventDefault();
    state.banner = { text: $("bannerText").value.trim(), on: $("bannerOn").checked };
    save();
    toast("Banner saved");
    render();
  });

  $("promoForm").addEventListener("submit", (e) => {
    e.preventDefault();
    const code = $("newCode").value.trim().toUpperCase().replace(/\s+/g, "");
    const value = Number($("newValue").value);
    const type = $("newType").value;
    if (!code || !(value > 0) || (type === "percent" && value > 100)) {
      toast("Enter a code and a valid value");
      return;
    }
    state.promos[code] = { type, value, uses: state.promos[code]?.uses || 0 };
    save();
    e.target.reset();
    toast("Promo " + code + " saved");
    render();
  });

  $("marketing").addEventListener("click", (e) => {
    const del = e.target.closest("[data-delpromo]");
    const unsub = e.target.closest("[data-unsub]");
    if (del) {
      delete state.promos[del.dataset.delpromo];
      if (state.appliedPromo === del.dataset.delpromo) state.appliedPromo = null;
    } else if (unsub) {
      state.subscribers = state.subscribers.filter((s) => s !== unsub.dataset.unsub);
    } else return;
    save();
    render();
  });

  $("featureList").addEventListener("change", (e) => {
    const cb = e.target.closest("[data-feature]");
    if (!cb) return;
    product(cb.dataset.feature).featured = cb.checked;
    save();
    render();
  });

  $("subscribeForm").addEventListener("submit", (e) => {
    e.preventDefault();
    const email = $("subEmail").value.trim().toLowerCase();
    if (!state.subscribers.includes(email)) state.subscribers.push(email);
    save();
    e.target.reset();
    render();
  });

  $("exportSubs").addEventListener("click", () => {
    const blob = new Blob(["email\n" + state.subscribers.join("\n")], { type: "text/csv" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "subscribers.csv";
    a.click();
    URL.revokeObjectURL(a.href);
  });

  $("resetData").addEventListener("click", () => {
    if (!confirm("Reset all products, orders, reviews and marketing data?")) return;
    state = structuredClone(SEED);
    save();
    toast("Demo data reset");
    render();
  });

  // ===== Render all =====
  function render() {
    renderBanner();
    renderCategories();
    renderStore();
    renderCart();
    renderOrders();
    renderMarketing();
  }

  render();

  // Deep link: /shop/#p3 opens that product
  const hash = location.hash.slice(1);
  if (product(hash)) openProduct(hash);
})();
