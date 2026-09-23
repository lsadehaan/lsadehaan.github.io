---
layout: toolpage
title: Shop — Buy, Review & Promote
permalink: /shop/
manifest: /assets/shop/manifest.webmanifest
description: >-
  A browser-based demo storefront: browse products, add them to a cart,
  check out with promo codes, write and read star-rated reviews, and manage
  marketing campaigns, discount codes and newsletter sign-ups.
---

<link rel="stylesheet" href="{{ site.baseurl }}/assets/css/shop.css" />

# Shop

<div id="promoBanner" class="shop-banner" hidden></div>

<p>A demo storefront with reviews and marketing tools. Everything is stored locally in your browser — no real payments are taken. <a href="{{ site.baseurl }}/shop/privacy/">Privacy policy</a></p>

<div class="tab-container">
  <div class="tab-nav">
    <button class="tab-button active" data-tab="store">Store</button>
    <button class="tab-button" data-tab="cart">Cart <span id="cartCount" class="shop-badge">0</span></button>
    <button class="tab-button" data-tab="orders">Orders</button>
    <button class="tab-button" data-tab="marketing">Marketing</button>
  </div>

  <!-- ===== Store ===== -->
  <div id="store" class="tab-content" style="display:block;">
    <div class="shop-toolbar">
      <input id="searchInput" type="search" placeholder="Search products…" />
      <select id="categoryFilter"><option value="">All categories</option></select>
      <select id="sortSelect">
        <option value="featured">Featured</option>
        <option value="price-asc">Price: low to high</option>
        <option value="price-desc">Price: high to low</option>
        <option value="rating">Top rated</option>
        <option value="reviews">Most reviewed</option>
      </select>
    </div>
    <div id="productGrid" class="shop-grid"></div>
  </div>

  <!-- ===== Cart & Checkout ===== -->
  <div id="cart" class="tab-content">
    <h2>Your Cart</h2>
    <div id="cartItems"></div>
    <div id="cartSummary" class="shop-summary"></div>
    <form id="checkoutForm" class="shop-form" hidden>
      <h3>Checkout</h3>
      <div class="shop-row">
        <label>Promo code <input id="promoInput" type="text" placeholder="e.g. WELCOME10" /></label>
        <button type="button" id="applyPromo" class="shop-btn secondary">Apply</button>
      </div>
      <p id="promoMsg" class="shop-msg"></p>
      <label>Name <input id="custName" type="text" required /></label>
      <label>Email <input id="custEmail" type="email" required /></label>
      <label>Shipping address <textarea id="custAddress" rows="2" required></textarea></label>
      <label class="shop-check"><input id="custOptIn" type="checkbox" checked /> Send me deals and news</label>
      <button type="submit" class="shop-btn">Place order</button>
    </form>
  </div>

  <!-- ===== Orders ===== -->
  <div id="orders" class="tab-content">
    <h2>Order History</h2>
    <p>After an order arrives, you can review what you bought here.</p>
    <div id="orderList"></div>
  </div>

  <!-- ===== Marketing ===== -->
  <div id="marketing" class="tab-content">
    <h2>Marketing Dashboard</h2>
    <div id="stats" class="shop-stats"></div>

    <div class="hex-subtool">
      <h3>Site Banner Campaign</h3>
      <form id="bannerForm" class="shop-form">
        <label>Banner message <input id="bannerText" type="text" placeholder="Autumn sale — 20% off with AUTUMN20" /></label>
        <label class="shop-check"><input id="bannerOn" type="checkbox" /> Show banner on the store</label>
        <button type="submit" class="shop-btn">Save banner</button>
      </form>
    </div>

    <div class="hex-subtool">
      <h3>Promo Codes</h3>
      <form id="promoForm" class="shop-form shop-inline">
        <input id="newCode" type="text" placeholder="CODE" required />
        <select id="newType">
          <option value="percent">% off</option>
          <option value="fixed">$ off</option>
        </select>
        <input id="newValue" type="number" min="1" step="1" placeholder="Value" required />
        <button type="submit" class="shop-btn">Add code</button>
      </form>
      <table class="shop-table" id="promoTable"></table>
    </div>

    <div class="hex-subtool">
      <h3>Featured Products</h3>
      <p>Featured products show first in the store and carry a “Featured” badge.</p>
      <div id="featureList" class="shop-feature-list"></div>
    </div>

    <div class="hex-subtool">
      <h3>Newsletter Subscribers</h3>
      <form id="subscribeForm" class="shop-form shop-inline">
        <input id="subEmail" type="email" placeholder="email@example.com" required />
        <button type="submit" class="shop-btn">Add subscriber</button>
        <button type="button" id="exportSubs" class="shop-btn secondary">Export CSV</button>
      </form>
      <ul id="subList" class="shop-list"></ul>
    </div>

    <div class="hex-subtool">
      <h3>Reset Demo Data</h3>
      <button type="button" id="resetData" class="shop-btn danger">Reset everything</button>
    </div>
  </div>
</div>

<!-- Product detail / reviews modal -->
<div id="productModal" class="shop-modal" hidden>
  <div class="shop-modal-box" role="dialog" aria-modal="true">
    <button class="shop-modal-close" aria-label="Close">&times;</button>
    <div id="modalBody"></div>
  </div>
</div>

<div id="toast" class="shop-toast" hidden></div>

<script src="{{ site.baseurl }}/assets/js/shop.js"></script>
<script>
  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("{{ site.baseurl }}/shop/sw.js");
  }
</script>
