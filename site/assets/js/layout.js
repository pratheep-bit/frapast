/**
 * layout.js — Single-source navbar and footer for all frapAST site pages.
 *
 * Each HTML page only needs:
 *   <main id="main-content">...</main>   (nav injected before it, footer after body)
 *   <script src="(../)?assets/js/layout.js"></script>  (before </body>)
 *
 * The script auto-detects depth (root vs docs/) so all links resolve correctly.
 */

(function () {
    const inDocs = window.location.pathname.includes('/docs/');
    const root   = inDocs ? '../' : '';
    const docsP  = inDocs ? ''    : 'docs/';
    const currentFile = window.location.pathname.split('/').pop() || 'index.html';

    function active(filename) {
        return currentFile === filename ? ' class="active"' : '';
    }

    function navActive(targetFile) {
        if (currentFile === targetFile) return ' class="active"';
        if (targetFile === 'getting-started.html' && inDocs) return ' class="active"';
        return '';
    }

    const githubSvg = `<svg height="16" width="16" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>`;

    const navHtml = `
    <a href="#main-content" class="skip-link">Skip to main content</a>
    <nav class="top" aria-label="Main Navigation">
        <div class="wrap">
            <div class="brand-group">
                <a href="${root}index.html" class="brand-link" style="display:flex;align-items:center;gap:10px;text-decoration:none;">
                    <img src="${root}assets/logo.png" alt="frapAST" class="brand-logo" width="32" height="32">
                    <span class="wordmark">frap<span>AST</span></span>
                </a>
            </div>
            <div class="nav-links">
                <a href="${root}${docsP}getting-started.html"${navActive('getting-started.html')}>Docs</a>
                <a href="${root}${docsP}rules.html"${navActive('rules.html')}>Rules</a>
                <a href="${root}changelog.html"${navActive('changelog.html')}>Changelog</a>
                <a href="${root}community.html"${navActive('community.html')}>Community</a>
            </div>
            <div class="nav-cta-group">
                <a href="https://github.com/pratheep-bit/frapast" class="btn-github" target="_blank" rel="noopener noreferrer" aria-label="View frapAST on GitHub">
                    ${githubSvg}
                    <span>GitHub</span>
                </a>
                <button class="mobile-toggle" type="button" aria-expanded="false" aria-controls="mobile-nav" aria-label="Toggle menu">
                    <svg class="icon icon-menu" viewBox="0 0 24 24" aria-hidden="true"><line x1="3" y1="12" x2="21" y2="12"></line><line x1="3" y1="6" x2="21" y2="6"></line><line x1="3" y1="18" x2="21" y2="18"></line></svg>
                    <svg class="icon icon-close" viewBox="0 0 24 24" aria-hidden="true"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
                </button>
            </div>
        </div>
        <div id="mobile-nav" class="mobile-nav" aria-label="Mobile Navigation">
            <a href="${root}index.html"${active('index.html')}>Home</a>
            <a href="${root}${docsP}getting-started.html"${active('getting-started.html')}>Getting Started</a>
            <a href="${root}${docsP}rules.html"${active('rules.html')}>Security Rules</a>
            <a href="${root}${docsP}cli-reference.html"${active('cli-reference.html')}>CLI Reference</a>
            <a href="${root}${docsP}github-action.html"${active('github-action.html')}>GitHub Action</a>
            <a href="${root}${docsP}faq.html"${active('faq.html')}>FAQ</a>
            <a href="${root}changelog.html"${active('changelog.html')}>Changelog</a>
            <a href="${root}community.html"${active('community.html')}>Community &amp; Contributing</a>
            <a href="https://github.com/pratheep-bit/frapast" target="_blank" rel="noopener noreferrer">View on GitHub</a>
        </div>
    </nav>`;

    const footerHtml = `
    <footer>
        <div class="wrap">
            <div class="footer-grid">
                <div class="footer-brand">
                    <a href="${root}index.html" class="brand-link" style="display:flex;align-items:center;gap:10px;text-decoration:none;margin-bottom:12px;">
                        <img src="${root}assets/logo.png" alt="frapAST" class="brand-logo" width="28" height="28">
                        <span class="wordmark">frap<span>AST</span></span>
                    </a>
                    <p>Runtime-proven static security and performance engine for Frappe and ERPNext applications.</p>
                </div>
                <div class="footer-col">
                    <h4>Documentation</h4>
                    <ul>
                        <li><a href="${root}${docsP}getting-started.html">Getting Started</a></li>
                        <li><a href="${root}${docsP}rules.html">Rule Taxonomy</a></li>
                        <li><a href="${root}${docsP}cli-reference.html">CLI Reference</a></li>
                        <li><a href="${root}${docsP}github-action.html">GitHub Action</a></li>
                        <li><a href="${root}${docsP}faq.html">Documentation FAQ</a></li>
                    </ul>
                </div>
                <div class="footer-col">
                    <h4>Project</h4>
                    <ul>
                        <li><a href="${root}changelog.html">Changelog (v0.1.0)</a></li>
                        <li><a href="${root}community.html">Community &amp; Roadmap</a></li>
                        <li><a href="${root}community.html#contributing">Contributing Guide</a></li>
                        <li><a href="${root}community.html#security">Security Policy</a></li>
                    </ul>
                </div>
                <div class="footer-col">
                    <h4>Open Source</h4>
                    <ul>
                        <li><a href="https://github.com/pratheep-bit/frapast" target="_blank" rel="noopener noreferrer">GitHub Repository</a></li>
                        <li><a href="https://github.com/pratheep-bit/frapast/issues" target="_blank" rel="noopener noreferrer">Issue Tracker</a></li>
                        <li><a href="https://github.com/pratheep-bit/frapast/blob/main/LICENSE" target="_blank" rel="noopener noreferrer">MIT License</a></li>
                        <li><a href="https://pypi.org/project/frapast/" target="_blank" rel="noopener noreferrer">PyPI Package</a></li>
                    </ul>
                </div>
            </div>
            <div class="footer-bottom">
                <p>Released under the MIT License &middot; 100% Local &amp; Air-Gapped &middot; Zero External Telemetry</p>
                <p>&copy; 2026 frapAST Contributors</p>
            </div>
        </div>
    </footer>`;

    function initMobileToggle() {
        const mobileToggle = document.querySelector('.mobile-toggle');
        const mobileNav    = document.querySelector('.mobile-nav');
        if (!mobileToggle || !mobileNav) return;

        mobileToggle.addEventListener('click', () => {
            const isExpanded = mobileToggle.getAttribute('aria-expanded') === 'true';
            mobileToggle.setAttribute('aria-expanded', String(!isExpanded));
            mobileNav.classList.toggle('open', !isExpanded);
        });

        // Close on Escape
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && mobileNav.classList.contains('open')) {
                mobileToggle.setAttribute('aria-expanded', 'false');
                mobileNav.classList.remove('open');
                mobileToggle.focus();
            }
        });

        // Close when tapping any mobile nav link
        mobileNav.addEventListener('click', (e) => {
            if (e.target.tagName === 'A') {
                mobileToggle.setAttribute('aria-expanded', 'false');
                mobileNav.classList.remove('open');
            }
        });
    }

    function inject() {
        const main = document.querySelector('main');
        if (main) {
            main.insertAdjacentHTML('beforebegin', navHtml);
        } else {
            document.body.insertAdjacentHTML('afterbegin', navHtml);
        }
        document.body.insertAdjacentHTML('beforeend', footerHtml);

        // Bind mobile toggle immediately after injection — never misses the element.
        initMobileToggle();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', inject);
    } else {
        inject();
    }
})();
