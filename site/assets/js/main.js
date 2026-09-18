/* ==========================================================================
   frapAST Main Interactive Scripts
   Mobile nav, custom nav dropdown, FAQ accordion, copy-to-clipboard,
   and live GitHub stats. Icon swaps are handled in CSS via [aria-expanded]
   selectors, so this file only ever toggles state — never emoji glyphs.
   ========================================================================== */

document.addEventListener('DOMContentLoaded', () => {
    const GITHUB_REPO = 'pratheep-bit/frapast';

    // 1. Mobile Menu Toggle
    // Binding is now owned by layout.js (injected immediately after DOM insertion).
    // Collapsible "Docs" group inside the mobile panel (if present)
    document.addEventListener('click', (e) => {
        const trigger = e.target.closest('.mobile-nav-group-trigger');
        if (trigger) {
            const group = trigger.closest('.mobile-nav-group');
            if (group) {
                const isOpen = group.classList.toggle('open');
                trigger.setAttribute('aria-expanded', String(isOpen));
            }
        }
    });

    // 2. Custom Desktop Nav Dropdown ("Docs")
    // A hand-built menu (not a native <select>) — keyboard accessible,
    // closes on outside click / Escape, single-open-at-a-time.
    const navItems = document.querySelectorAll('.nav-item');
    if (navItems.length) {
        const closeItem = (item) => {
            item.classList.remove('open');
            const trigger = item.querySelector('.nav-dropdown-trigger');
            if (trigger) trigger.setAttribute('aria-expanded', 'false');
        };
        const closeAllExcept = (except) => {
            navItems.forEach((item) => { if (item !== except) closeItem(item); });
        };

        navItems.forEach((item) => {
            const trigger = item.querySelector('.nav-dropdown-trigger');
            const panel = item.querySelector('.nav-dropdown-panel');
            if (!trigger || !panel) return;

            trigger.addEventListener('click', (e) => {
                e.stopPropagation();
                const willOpen = !item.classList.contains('open');
                closeAllExcept(null);
                if (willOpen) {
                    item.classList.add('open');
                    trigger.setAttribute('aria-expanded', 'true');
                }
            });

            trigger.addEventListener('keydown', (e) => {
                if (e.key === 'ArrowDown' || e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    closeAllExcept(item);
                    item.classList.add('open');
                    trigger.setAttribute('aria-expanded', 'true');
                    const first = panel.querySelector('.nav-dropdown-link');
                    if (first) first.focus();
                } else if (e.key === 'Escape') {
                    closeItem(item);
                    trigger.focus();
                }
            });

            panel.addEventListener('keydown', (e) => {
                if (e.key === 'Escape') {
                    closeItem(item);
                    trigger.focus();
                }
            });
        });

        document.addEventListener('click', () => closeAllExcept(null));
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') closeAllExcept(null);
        });
    }

    // 3. Copy-to-Clipboard Buttons
    // Buttons wrap their text in <span class="copy-label"> so the icon
    // survives the "Copied" state swap.
    async function copyText(text) {
        if (navigator.clipboard && window.isSecureContext) {
            await navigator.clipboard.writeText(text);
            return;
        }
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        try { document.execCommand('copy'); } catch (err) { /* clipboard unavailable */ }
        document.body.removeChild(textarea);
    }

    // Delegated copy-to-clipboard — works for elements injected after DOMContentLoaded
    // (e.g. rule cards rendered by rules.js) without needing a re-query.
    document.addEventListener('click', async (e) => {
        const btn = e.target.closest('[data-copy]');
        if (!btn) return;

        const textToCopy = btn.getAttribute('data-copy');
        if (!textToCopy) return;

        try {
            await copyText(textToCopy);
            const label = btn.querySelector('.copy-label');
            const original = label ? label.textContent : btn.textContent;
            btn.classList.add('copied');
            if (label) label.textContent = 'Copied';
            else btn.textContent = 'Copied';

            setTimeout(() => {
                btn.classList.remove('copied');
                if (label) label.textContent = original;
                else btn.textContent = original;
            }, 1500);
        } catch (err) {
            console.warn('Clipboard write failed:', err);
        }
    });

    // 4. FAQ Accordion
    const faqItems = document.querySelectorAll('.faq-item');
    faqItems.forEach(item => {
        const questionBtn = item.querySelector('.faq-question');
        if (!questionBtn) return;

        questionBtn.addEventListener('click', () => {
            const isOpen = item.classList.contains('open');
            // Close other open items so only one answer shows at a time
            faqItems.forEach(other => {
                if (other !== item) {
                    other.classList.remove('open');
                    const otherBtn = other.querySelector('.faq-question');
                    if (otherBtn) otherBtn.setAttribute('aria-expanded', 'false');
                }
            });

            item.classList.toggle('open', !isOpen);
            questionBtn.setAttribute('aria-expanded', String(!isOpen));
        });
    });

    // 5. Live GitHub Stats via Public REST API, with Graceful Fallback
    // Star/issue counts render as an icon + <span class="copy-label"> so
    // there is never a raw star glyph in the markup.
    const starEls = document.querySelectorAll('[data-github-stars]');
    const issueEls = document.querySelectorAll('[data-github-issues]');
    const releaseTagEl = document.querySelector('[data-github-release]');

    function setLabel(el, text) {
        const label = el.querySelector('.copy-label');
        if (label) label.textContent = text;
        else el.textContent = text;
    }

    function formatCount(n) {
        if (n >= 1000) return (n / 1000).toFixed(1).replace(/\.0$/, '') + 'k';
        return String(n);
    }

    if (starEls.length || issueEls.length) {
        fetch(`https://api.github.com/repos/${GITHUB_REPO}`, { headers: { Accept: 'application/vnd.github+json' } })
            .then(res => {
                if (!res.ok) throw new Error(`HTTP ${res.status}`);
                return res.json();
            })
            .then(data => {
                if (typeof data.stargazers_count === 'number') {
                    starEls.forEach(el => setLabel(el, formatCount(data.stargazers_count)));
                }
                if (typeof data.open_issues_count === 'number') {
                    issueEls.forEach(el => setLabel(el, `${formatCount(data.open_issues_count)} open`));
                }
            })
            .catch(err => {
                // Offline or rate-limited: keep the static fallback already in the markup.
                console.debug('GitHub public API fetch skipped:', err.message);
            });
    }

    if (releaseTagEl) {
        fetch(`https://api.github.com/repos/${GITHUB_REPO}/releases/latest`)
            .then(res => {
                if (!res.ok) throw new Error(`HTTP ${res.status}`);
                return res.json();
            })
            .then(data => {
                if (data.tag_name) releaseTagEl.textContent = data.tag_name;
            })
            .catch(() => {
                releaseTagEl.textContent = 'v1.0.0';
            });
    }

    // 6. Automatic Terminal & Code Syntax Highlighting (Authentic Frappe Theme)
    function escapeHtml(s) {
        return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    const TOKEN_SPECS = [
        ['COMMENT',   /(^|\s)#.*$/],
        ['HEADER',    /^(usage:|positional arguments:|options:|optional arguments:|Examples:|Commands:|Target:)/i],
        ['DECORATOR', /@[a-zA-Z0-9_\.]+/],
        ['KEYWORD',   /\b(def|return|from|import|if|elif|else|for|while|try|except|finally|with|as|in|is|not|and|or|None|True|False|class|pass|raise)\b/],
        ['FLAG',      /(^|\s)(--[a-zA-Z0-9_\-]+|-[a-zA-Z0-9])(?=\s|[,\)\]]|$)/],
        ['CMD',       /\b(frapast|pip3?|python3?|git|pytest|ruff)\b/],
        ['SUBCMD',    /\b(bench-check|fp-report|scan|prove|fix|report|shell|bench|pr|clone|install|check)\b/],
        ['STATUS_OK', /\[PASS\]|Tier 1 Verified|PASSED|PROVEN/],
        ['STATUS_ERR',/\[FAIL\]|\[CRITICAL\]|\[HIGH\]|VULNERABILITY|REFUTED/],
        ['STATUS_WARN',/\[WARN\]|\[MEDIUM\]|\[LOW\]/],
        ['PROMPT',    /^(\$|&gt;)\s/],
        ['STRING',    /(&quot;.*?&quot;|&#39;.*?&#39;|"[^"]*"|'[^']*')/]
    ];

    const combinedRegex = new RegExp(TOKEN_SPECS.map(([name, pat]) => `(?<${name}>${pat.source})`).join('|'), 'g');

    function highlightCode(raw) {
        if (!raw) return '';
        const lines = raw.split('\n');
        return lines.map(line => {
            if (!line) return '';
            const trimmed = line.trimStart();
            if (trimmed.startsWith('#') || trimmed.startsWith('//')) {
                return `<span class="t-comment">${escapeHtml(line)}</span>`;
            }

            const escaped = escapeHtml(line);
            return escaped.replace(combinedRegex, (match, ...args) => {
                const groups = args[args.length - 1] || {};
                for (const [name] of TOKEN_SPECS) {
                    if (groups[name]) {
                        switch (name) {
                            case 'COMMENT': return `<span class="t-comment">${match}</span>`;
                            case 'HEADER': return `<span class="t-header">${match}</span>`;
                            case 'DECORATOR': return `<span class="t-decorator">${match}</span>`;
                            case 'KEYWORD': return `<span class="t-kw">${match}</span>`;
                            case 'FLAG': return `<span class="t-flag">${match}</span>`;
                            case 'CMD': return `<span class="t-cmd">${match}</span>`;
                            case 'SUBCMD': return `<span class="t-subcmd">${match}</span>`;
                            case 'STATUS_OK': return `<span class="t-pass">${match}</span>`;
                            case 'STATUS_ERR': return `<span class="t-fail">${match}</span>`;
                            case 'STATUS_WARN': return `<span class="t-warn">${match}</span>`;
                            case 'PROMPT': return `<span class="t-prompt">${match}</span>`;
                            case 'STRING': return `<span class="t-str">${match}</span>`;
                        }
                    }
                }
                return match;
            });
        }).join('\n');
    }

    window.highlightCode = highlightCode;

    // Run on all code blocks across the site
    function applyHighlighting() {
        document.querySelectorAll('.code-block pre code, .code-block code, pre.diff-code').forEach(codeEl => {
            if (codeEl.id === 'action-yaml-output' || codeEl.dataset.highlighted === 'true') return;
            const raw = codeEl.textContent;
            if (raw && raw.trim().length > 0) {
                codeEl.innerHTML = highlightCode(raw);
                codeEl.dataset.highlighted = 'true';
            }
        });
    }

    applyHighlighting();
    // Also re-check once in case elements rendered slightly after
    setTimeout(applyHighlighting, 100);
});