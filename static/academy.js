
(function () {
    'use strict';

    var CHAPTERS = window.ACADEMY_CHAPTERS || [];
    var STORE_KEY = 'bw-academy-v1';
    var MISSION_ORDER = [];
    var HINT_COST = 20;

    var CAPTURES = {
        sample: {
            name: function () { return window.SAMPLE_CAPTURE_NAME || 'sample.pcap'; },
            data: function () { return window.SAMPLE_CAPTURE_BASE64 || ''; }
        },
        academy: {
            name: function () {
                return (window.ACADEMY_CAPTURES && window.ACADEMY_CAPTURES.academy.name) || 'academy.pcap';
            },
            data: function () {
                return (window.ACADEMY_CAPTURES && window.ACADEMY_CAPTURES.academy.base64) || '';
            }
        },
        trouble: {
            name: function () {
                return (window.ACADEMY_CAPTURES && window.ACADEMY_CAPTURES.trouble.name) || 'trouble.pcap';
            },
            data: function () {
                return (window.ACADEMY_CAPTURES && window.ACADEMY_CAPTURES.trouble.base64) || '';
            }
        },
        advanced: {
            name: function () {
                return (window.ACADEMY_CAPTURES && window.ACADEMY_CAPTURES.advanced.name) || 'advanced.pcap';
            },
            data: function () {
                return (window.ACADEMY_CAPTURES && window.ACADEMY_CAPTURES.advanced.base64) || '';
            }
        },
        threat: {
            name: function () {
                return (window.ACADEMY_CAPTURES && window.ACADEMY_CAPTURES.threat.name) || 'threat.pcap';
            },
            data: function () {
                return (window.ACADEMY_CAPTURES && window.ACADEMY_CAPTURES.threat.base64) || '';
            }
        },
        ipv6: {
            name: function () {
                return (window.ACADEMY_CAPTURES && window.ACADEMY_CAPTURES.ipv6.name) || 'ipv6.pcap';
            },
            data: function () {
                return (window.ACADEMY_CAPTURES && window.ACADEMY_CAPTURES.ipv6.base64) || '';
            }
        },
        web: {
            name: function () {
                return (window.ACADEMY_CAPTURES && window.ACADEMY_CAPTURES.web.name) || 'web.pcap';
            },
            data: function () {
                return (window.ACADEMY_CAPTURES && window.ACADEMY_CAPTURES.web.base64) || '';
            }
        },
        encrypted: {
            name: function () {
                return (window.ACADEMY_CAPTURES && window.ACADEMY_CAPTURES.encrypted.name) || 'encrypted.pcap';
            },
            data: function () {
                return (window.ACADEMY_CAPTURES && window.ACADEMY_CAPTURES.encrypted.base64) || '';
            }
        },
        malware: {
            name: function () {
                return (window.ACADEMY_CAPTURES && window.ACADEMY_CAPTURES.malware.name) || 'malware.pcap';
            },
            data: function () {
                return (window.ACADEMY_CAPTURES && window.ACADEMY_CAPTURES.malware.base64) || '';
            }
        },
        c2: {
            name: function () {
                return (window.ACADEMY_CAPTURES && window.ACADEMY_CAPTURES.c2.name) || 'c2.pcap';
            },
            data: function () {
                return (window.ACADEMY_CAPTURES && window.ACADEMY_CAPTURES.c2.base64) || '';
            }
        }
    };

    var LEVELS = [
        { xp: 0, name: 'Curious' },
        { xp: 500, name: 'Packet Scout' },
        { xp: 1200, name: 'Filter Pilot' },
        { xp: 2200, name: 'Protocol Detective' },
        { xp: 3300, name: 'Stream Whisperer' },
        { xp: 4550, name: 'Traffic Analyst' },
        { xp: 5950, name: 'Incident Responder' },
        { xp: 7450, name: 'Threat Hunter' },
        { xp: 9100, name: 'Packet Whisperer' },
        { xp: 10900, name: 'Network Forensicist' },
        { xp: 12800, name: 'Packet Oracle' },
        { xp: 14900, name: 'Packet Sage' }
    ];

    var PANELS = {
        'Follow TCP Stream': 'follow',
        'Follow UDP Stream': 'follow',
        'Protocol Hierarchy': 'hierarchy',
        'Conversations': 'conversations',
        'Endpoints': 'endpoints',
        'IO Graph': 'io',
        'Expert Information': 'expert',
        'HTTP Objects': 'http',
        'Coloring Rules': 'colors',
        'Column Preferences': 'columns',
        'Capture File Properties': 'properties'
    };

    CHAPTERS.forEach(function (chapter) {
        chapter.missions.forEach(function (mission) {
            MISSION_ORDER.push({
                mission: mission,
                chapter: chapter,
                chapterIndex: CHAPTERS.indexOf(chapter),
                number: MISSION_ORDER.length + 1
            });
        });
    });

    var progress = loadProgress();
    var session = null;
    var els = {};

    function loadProgress() {
        try {
            var raw = localStorage.getItem(STORE_KEY);
            if (raw) {
                var parsed = JSON.parse(raw);
                if (parsed && typeof parsed.xp === 'number' && parsed.completed) {
                    return { xp: parsed.xp, completed: parsed.completed };
                }
            }
        } catch (e) { }
        return { xp: 0, completed: {} };
    }

    function saveProgress() {
        try { localStorage.setItem(STORE_KEY, JSON.stringify(progress)); } catch (e) { }
    }

    function isCompleted(id) {
        return !!(progress.completed && progress.completed[id]);
    }

    function completedCount() {
        return MISSION_ORDER.filter(function (item) { return isCompleted(item.mission.id); }).length;
    }

    function chapterComplete(chapter) {
        return chapter.missions.every(function (m) { return isCompleted(m.id); });
    }

    function levelFor(xp) {
        var index = 0;
        for (var i = 0; i < LEVELS.length; i++) if (xp >= LEVELS[i].xp) index = i;
        var current = LEVELS[index];
        var next = LEVELS[index + 1] || null;
        return { index: index, name: current.name, base: current.xp, next: next ? next.xp : null };
    }

    function esc(value) {
        return String(value == null ? '' : value).replace(/[&<>"']/g, function (c) {
            return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
        });
    }

    function tickSvg() {
        return '<svg class="bw-tick-icon" viewBox="0 0 16 16" aria-hidden="true" focusable="false">' +
            '<path d="M2.9 8.5 6.2 11.8 13.1 4.4" fill="none" stroke="currentColor" ' +
            'stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>' +
            '</svg>';
    }

    function normalizeExpr(expr) {
        return String(expr || '')
            .toLowerCase()
            .replace(/\s+(and|or|not)\s+/g, function (m, op) {
                return op === 'and' ? '&&' : op === 'or' ? '||' : '!';
            })
            .replace(/\beq\b/g, '==')
            .replace(/\bne\b/g, '!=')
            .replace(/\bgt\b/g, '>')
            .replace(/\bge\b/g, '>=')
            .replace(/\blt\b/g, '<')
            .replace(/\ble\b/g, '<=')
            .replace(/\s+/g, '');
    }

    function missionEntry(id) {
        for (var i = 0; i < MISSION_ORDER.length; i++) {
            if (MISSION_ORDER[i].mission.id === id) return MISSION_ORDER[i];
        }
        return null;
    }

    function nextMissionEntry() {
        for (var i = 0; i < MISSION_ORDER.length; i++) {
            if (!isCompleted(MISSION_ORDER[i].mission.id)) return MISSION_ORDER[i];
        }
        return null;
    }

    function isUnlocked(index) {
        if (index <= 0) return true;
        return isCompleted(MISSION_ORDER[index - 1].mission.id);
    }

    function base64ToFile(key) {
        var cap = CAPTURES[key];
        if (!cap) return null;
        var data = cap.data();
        if (!data) return null;
        var binary;
        try { binary = atob(data); } catch (e) { return null; }
        var bytes = new Uint8Array(binary.length);
        for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        var name = cap.name();
        try {
            return new File([bytes], name, { type: 'application/vnd.tcpdump.pcap' });
        } catch (e) {
            return new Blob([bytes], { type: 'application/vnd.tcpdump.pcap' });
        }
    }

    function renderHud() {
        var level = levelFor(progress.xp);
        var span = level.next ? (level.next - level.base) : 1;
        var into = progress.xp - level.base;
        var pct = level.next ? Math.max(0, Math.min(100, (into / span) * 100)) : 100;
        var done = completedCount();

        if (els.levelName) els.levelName.textContent = level.name;
        if (els.xpTotal) els.xpTotal.textContent = progress.xp + ' XP';
        if (els.missionCount) els.missionCount.textContent = done + ' / ' + MISSION_ORDER.length + ' missions';
        if (els.xpFill) els.xpFill.style.width = pct + '%';
        if (els.xpNote) {
            els.xpNote.textContent = level.next
                ? (level.next - progress.xp) + ' XP to ' + LEVELS[level.index + 1].name
                : 'Maximum level reached';
        }

        if (els.badges) {
            els.badges.innerHTML = CHAPTERS.map(function (chapter) {
                var earned = chapterComplete(chapter);
                return '<span class="bw-badge' + (earned ? ' earned' : '') + '" title="' +
                    (earned ? 'Earned: ' : 'Locked: ') + esc(chapter.badge.name) + '">' +
                    '<span class="bw-badge-icon">' + esc(chapter.badge.icon) + '</span>' +
                    esc(chapter.badge.name) + '</span>';
            }).join('');
        }

        var next = nextMissionEntry();
        if (els.startBtn) {
            els.startBtn.textContent = next
                ? (progress.xp === 0 ? 'Start training' : 'Continue: ' + next.mission.title)
                : 'Review a mission';
            els.startBtn.disabled = false;
        }
    }

    function renderMap() {
        if (!els.map) return;
        var done = completedCount();
        if (els.mapSummary) {
            els.mapSummary.textContent = done
                ? done + ' of ' + MISSION_ORDER.length + ' missions complete. Replay anything to sharpen the skill.'
                : 'Start at mission 1. Each mission unlocks the next one.';
        }

        els.map.innerHTML = CHAPTERS.map(function (chapter) {
            var finished = chapterComplete(chapter);
            var missionsHtml = chapter.missions.map(function (mission) {
                var entry = missionEntry(mission.id);
                var completed = isCompleted(mission.id);
                var unlocked = isUnlocked(entry.number - 1);
                var state = completed ? 'done' : (unlocked ? 'open' : 'locked');
                var record = progress.completed[mission.id];
                var meta = completed
                    ? '<span class="bw-mission-meta">' + (record ? record.xp : mission.xp) + ' XP earned · replay</span>'
                    : '<span class="bw-mission-meta">' + mission.xp + ' XP · ' + mission.tasks.length + ' steps</span>';
                return '<button type="button" class="bw-mission ' + state + '" data-mission="' + esc(mission.id) + '"' +
                    (unlocked ? '' : ' disabled aria-disabled="true"') + '>' +
                    '<span class="bw-mission-flag">' + (completed ? tickSvg() : unlocked ? String(entry.number).padStart(2, '0') : '🔒') + '</span>' +
                    '<span class="bw-mission-text">' +
                        '<span class="bw-mission-title">' + esc(mission.title) + '</span>' +
                        meta +
                    '</span>' +
                    '<span class="bw-mission-arrow">' + (unlocked ? '→' : '') + '</span>' +
                '</button>';
            }).join('');

            return '<section class="bw-chapter' + (finished ? ' finished' : '') + '" aria-labelledby="ch-' + chapter.id + '">' +
                '<div class="bw-chapter-head">' +
                    '<div class="bw-chapter-title">' +
                        '<span class="bw-chapter-no">CHAPTER ' + chapter.number + '</span>' +
                        '<h2 id="ch-' + chapter.id + '">' + esc(chapter.title) + '</h2>' +
                        '<p>' + esc(chapter.tagline) + '</p>' +
                    '</div>' +
                    '<div class="bw-chapter-side">' +
                        (chapter.level
                            ? '<span class="bw-chapter-level lvl-' +
                                esc(String(chapter.level).toLowerCase().replace(/\s+/g, '-')) + '">' +
                                esc(chapter.level) + '</span>'
                            : '') +
                        '<span class="bw-chapter-badge' + (finished ? ' earned' : '') + '">' +
                            esc(chapter.badge.icon) + ' ' + esc(chapter.badge.name) +
                        '</span>' +
                        '<span class="bw-chapter-progress">' +
                            chapter.missions.filter(function (m) { return isCompleted(m.id); }).length +
                            '/' + chapter.missions.length +
                        '</span>' +
                    '</div>' +
                '</div>' +
                '<div class="bw-mission-grid">' + missionsHtml + '</div>' +
            '</section>';
        }).join('');
    }

    function startMission(id) {
        var entry = missionEntry(id);
        if (!entry) return;
        if (typeof window.openPcapViewer !== 'function') return;

        var file = base64ToFile(entry.chapter.capture);
        if (!file) {
            if (els.error) {
                els.error.textContent = 'That capture could not be loaded. Reload the page and try again.';
                els.error.hidden = false;
            }
            return;
        }

        if (session && session.dock) session.dock.remove();

        session = {
            mission: entry.mission,
            chapter: entry.chapter,
            number: entry.number,
            state: {
                captureName: '',
                offCapture: false,
                selections: {},
                fields: [],
                filters: [],
                dialogs: [],
                actions: [],
                marked: [],
                done: entry.mission.tasks.map(function () { return false; }),
                quizCorrect: {},
                quizWrong: {},
                blankWrong: {},
                blankValues: {},
                hintsRevealed: 0,
                completedNow: false
            },
            dock: null,
            expected: CAPTURES[entry.chapter.capture].name()
        };

        window.openPcapViewer(file, session.expected);

        var win = document.querySelector('.pcap-window');
        if (!win) { session = null; return; }
        win.classList.add('academy-docked');

        var dock = document.createElement('aside');
        dock.className = 'bw-dock';
        dock.setAttribute('aria-label', 'Academy mission panel');
        win.appendChild(dock);
        session.dock = dock;
        dock.addEventListener('click', onDockClick);
        dock.addEventListener('keydown', onDockKeydown);
        dock.addEventListener('input', onDockInput);
        renderDock();

        document.body.classList.add('academy-running');
        if (els.map) els.map.scrollTop = 0;
    }

    function onDockClick(e) {
        if (!session) return;
        var blankBtn = e.target.closest('[data-blank-check]');
        if (blankBtn) {
            checkBlank(parseInt(blankBtn.getAttribute('data-blank-check'), 10));
            return;
        }
        var quizBtn = e.target.closest('[data-quiz]');
        if (quizBtn) {
            answerQuiz(parseInt(quizBtn.getAttribute('data-quiz'), 10), parseInt(quizBtn.getAttribute('data-opt'), 10));
            return;
        }
        if (e.target.closest('[data-dock-close]')) {
            window.closePcapViewer();
            return;
        }
        if (e.target.closest('[data-dock-min]')) {
            var win = document.querySelector('.pcap-window');
            if (win) win.classList.toggle('academy-dock-min');
            if (session.dock) session.dock.classList.toggle('collapsed');
            return;
        }
        if (e.target.closest('[data-hint]')) {
            revealHint();
            return;
        }
        if (e.target.closest('[data-show]')) {
            demoTask();
            return;
        }
        if (e.target.closest('[data-next]')) {
            var next = nextMissionEntry();
            if (next) startMission(next.mission.id);
            else window.closePcapViewer();
            return;
        }
        if (e.target.closest('[data-map]')) {
            window.closePcapViewer();
            return;
        }
    }

    function onDockKeydown(e) {
        if (e.key !== 'Enter' || !session) return;
        var input = e.target.closest('[data-blank-input]');
        if (!input) return;
        e.preventDefault();
        checkBlank(parseInt(input.getAttribute('data-blank-input'), 10));
    }

    function onDockInput(e) {
        if (!session) return;
        var input = e.target.closest('[data-blank-input]');
        if (!input) return;
        var index = parseInt(input.getAttribute('data-blank-input'), 10);
        session.state.blankValues[index] = input.value;
        delete session.state.blankWrong[index];
        var feedback = session.dock.querySelector('[data-blank-feedback="' + index + '"]');
        if (feedback) feedback.hidden = true;
    }

    function normalizeBlank(value) {
        return String(value || '')
            .toLowerCase()
            .trim()
            .replace(/[`"']/g, '')
            .replace(/\s+/g, '')
            .replace(/[.;:]+$/, '');
    }

    function checkBlank(index) {
        if (!session) return;
        var task = session.mission.tasks[index];
        if (!task || !task.blank || session.state.done[index]) return;
        var input = session.dock.querySelector('[data-blank-input="' + index + '"]');
        if (!input) return;
        var value = input.value;
        if (!normalizeBlank(value)) {
            input.focus();
            return;
        }
        var accepted = [task.blank.answer].concat(task.blank.accept || []);
        var correct = accepted.some(function (answer) {
            return normalizeBlank(answer) === normalizeBlank(value);
        });
        if (!correct) {
            session.state.blankWrong[index] = true;
            input.classList.add('wrong');
            var feedback = session.dock.querySelector('[data-blank-feedback="' + index + '"]');
            if (feedback) {
                feedback.textContent = 'Not quite — try again.';
                feedback.hidden = false;
            }
            return;
        }
        session.state.blankValues[index] = value;
        delete session.state.blankWrong[index];
        session.state.done[index] = true;
        renderDock();
        maybeComplete();
    }

    function answerQuiz(index, option) {
        var mission = session.mission;
        var task = mission.tasks[index];
        if (!task || !task.quiz || session.state.done[index]) return;
        if (option === task.quiz.answer) {
            session.state.quizCorrect[index] = true;
            session.state.done[index] = true;
            delete session.state.quizWrong[index];
            renderDock();
            maybeComplete();
        } else {
            session.state.quizWrong[index] = option;
            renderDock();
        }
    }

    function revealHint() {
        var hints = session.mission.hints || [];
        if (session.state.hintsRevealed >= hints.length) return;
        session.state.hintsRevealed++;
        renderDock();
    }

    function demoTask() {
        var tasks = session.mission.tasks;
        var state = session.state;
        var index = -1;
        for (var i = 0; i < tasks.length; i++) {
            if (!state.done[i]) { index = i; break; }
        }
        if (index < 0) return;
        var task = tasks[index];

        // A quiz has no packet action to demonstrate: reveal the answer and
        // move on immediately.
        if (task.quiz) {
            state.quizCorrect[index] = true;
            state.done[index] = true;
            delete state.quizWrong[index];
            renderDock();
            maybeComplete();
            return;
        }

        // Fill-in-the-blank has no packet action either: show the answer and
        // advance immediately.
        if (task.blank) {
            state.blankValues[index] = task.blank.answer;
            delete state.blankWrong[index];
            state.done[index] = true;
            renderDock();
            maybeComplete();
            return;
        }

        var api = window.PcapAcademyApi;
        if (!api) return;

        if (task.select && task.select.no != null) {
            api.selectNo(task.select.no);
            return;
        }
        if (task.filter && task.filter.expr && task.filter.expr.length) {
            api.setFilter(task.filter.expr[0]);
            return;
        }
        if (task.dialog) {
            if (task.dialog[0].indexOf('Follow ') === 0) {
                var selected = null;
                for (var t = 0; t < tasks.length; t++) {
                    if (tasks[t].select && tasks[t].select.no != null) selected = tasks[t];
                }
                if (selected) api.selectNo(selected.select.no);
            }
            var panel = PANELS[task.dialog[0]];
            if (panel) { api.openPanel(panel); return; }
        }
        if (task.mark) {
            api.selectNo(task.mark[0]);
            api.markNo(task.mark[0], true);
            return;
        }
        revealHint();
    }

    function taskSatisfied(task, state) {
        if (task.quiz || task.blank) return false;
        if (task.select) {
            var snapshot = state.selections[task.select.no];
            return snapshot ? packetMatches(snapshot, task.select) : false;
        }
        if (task.filter) {
            var accepted = (task.filter.expr || []).map(normalizeExpr);
            return state.filters.some(function (f) {
                if (accepted.indexOf(normalizeExpr(f.expr)) === -1) return false;
                if (task.filter.matches != null && f.matches !== task.filter.matches) return false;
                return true;
            });
        }
        if (task.field) return state.fields.length > 0;
        if (task.dialog) {
            return task.dialog.some(function (title) {
                return state.dialogs.indexOf(title) !== -1;
            });
        }
        if (task.action) {
            return task.action.some(function (label) {
                return state.actions.some(function (action) { return action.label === label; });
            });
        }
        if (task.mark) {
            return task.mark.every(function (no) { return state.marked.indexOf(no) !== -1; });
        }
        return false;
    }

    function packetMatches(snapshot, sel) {
        if (!snapshot) return false;
        if (sel.no != null && snapshot.no !== sel.no) return false;
        if (sel.proto && String(snapshot.proto).toLowerCase() !== String(sel.proto).toLowerCase()) return false;
        if (sel.transport && snapshot.transport !== sel.transport) return false;
        if (sel.infoContains && snapshot.info.toLowerCase().indexOf(String(sel.infoContains).toLowerCase()) === -1) return false;
        if (sel.src && snapshot.src !== sel.src) return false;
        if (sel.dst && snapshot.dst !== sel.dst) return false;
        if (sel.srcport != null && Number(snapshot.srcport) !== Number(sel.srcport)) return false;
        if (sel.dstport != null && Number(snapshot.dstport) !== Number(sel.dstport)) return false;
        if (sel.fields) {
            for (var key in sel.fields) {
                if (!Object.prototype.hasOwnProperty.call(sel.fields, key)) continue;
                if (snapshot.fields[key] !== sel.fields[key]) return false;
            }
        }
        return true;
    }

    function evaluate() {
        if (!session) return;
        var changed = false;
        session.mission.tasks.forEach(function (task, index) {
            if (session.state.done[index]) return;
            if (task.quiz || task.blank) return;
            if (taskSatisfied(task, session.state)) {
                session.state.done[index] = true;
                changed = true;
            }
        });
        if (changed) {
            renderDock();
            maybeComplete();
        }
    }

    function maybeComplete() {
        if (!session || session.state.completedNow) return;
        if (!session.state.done.every(function (v) { return v; })) return;
        session.state.completedNow = true;

        var mission = session.mission;
        var replay = isCompleted(mission.id);
        var gained = 0;
        if (!replay) {
            gained = Math.max(40, mission.xp - session.state.hintsRevealed * HINT_COST);
            progress.xp += gained;
            progress.completed[mission.id] = {
                xp: gained,
                hints: session.state.hintsRevealed,
                date: new Date().toISOString().slice(0, 10)
            };
            saveProgress();
        }
        renderHud();
        renderMap();
        renderDock(gained, replay);
    }

    function renderDock(gained, replay) {
        if (!session || !session.dock) return;
        var dock = session.dock;
        var mission = session.mission;
        var chapter = session.chapter;
        var state = session.state;
        var body = dock.querySelector('.bw-dock-body');
        var scroll = body ? body.scrollTop : 0;

        if (state.completedNow) {
            var record = progress.completed[mission.id];
            var earned = record ? record.xp : (gained || 0);
            var badge = chapterComplete(chapter);
            var next = nextMissionEntry();
            var quizAnswers = mission.tasks.filter(function (t) { return !!t.quiz; }).map(function (t) {
                return '<div class="bw-win-answer">' +
                    '<p class="bw-win-answer-kicker">Answer</p>' +
                    '<p class="bw-win-answer-q">' + esc(t.quiz.q) + '</p>' +
                    '<p class="bw-win-answer-opt">' + String.fromCharCode(65 + t.quiz.answer) +
                        '. ' + esc(t.quiz.options[t.quiz.answer]) + '</p>' +
                    '<p class="bw-win-answer-explain">' + esc(t.quiz.explain) + '</p>' +
                '</div>';
            }).join('');
            var blankAnswers = mission.tasks.filter(function (t) { return !!t.blank; }).map(function (t) {
                return '<div class="bw-win-blank">' +
                    '<p class="bw-win-answer-kicker">Fill in the blank</p>' +
                    '<p class="bw-win-answer-q">' + esc(t.blank.q) + '</p>' +
                    '<p class="bw-win-answer-opt">' + esc(t.blank.answer) + '</p>' +
                    '<p class="bw-win-answer-explain">' + esc(t.blank.explain) + '</p>' +
                '</div>';
            }).join('');
            var quizAnswer = quizAnswers + blankAnswers;
            dock.innerHTML =
                '<div class="bw-dock-top">' +
                    '<div>' +
                        '<p class="bw-dock-kicker">Mission ' + String(session.number).padStart(2, '0') + ' complete</p>' +
                        '<h2 class="bw-dock-title">' + (replay ? 'Replay finished' : 'Nice work') + '</h2>' +
                    '</div>' +
                    '<div class="bw-dock-tools"><button type="button" data-dock-close class="bw-dock-tool" aria-label="Close">✕</button></div>' +
                '</div>' +
                '<div class="bw-dock-body">' +
                    '<div class="bw-win">' +
                        '<div class="bw-win-ring">' + tickSvg() + '</div>' +
                        '<p class="bw-win-xp">' + (replay ? '+0 XP' : '+' + earned + ' XP') + '</p>' +
                        '<p class="bw-win-title">' + esc(mission.title) + '</p>' +
                        quizAnswer +
                        (replay ? '<p class="bw-win-note">Already in your logbook. Replays keep your XP.</p>' : '') +
                        (state.hintsRevealed
                            ? '<p class="bw-win-note">' + state.hintsRevealed + ' hint' + (state.hintsRevealed > 1 ? 's' : '') + ' used (−' + (state.hintsRevealed * HINT_COST) + ' XP)</p>'
                            : '<p class="bw-win-note">No hints used. Clean run.</p>') +
                        (badge
                            ? '<div class="bw-win-badge">' + esc(chapter.badge.icon) + ' Badge earned: ' + esc(chapter.badge.name) + '</div>'
                            : '') +
                    '</div>' +
                '</div>' +
                '<div class="bw-dock-foot bw-win-actions">' +
                    (next
                        ? '<button type="button" class="bw-dock-btn primary" data-next>Next mission →</button>'
                        : '<button type="button" class="bw-dock-btn primary" data-map>Back to the map</button>') +
                    '<button type="button" class="bw-dock-btn" data-map>Mission map</button>' +
                '</div>';
            return;
        }

        var doneCount = state.done.filter(Boolean).length;
        var pct = Math.round((doneCount / mission.tasks.length) * 100);
        var taskHtml = mission.tasks.map(function (task, index) {
            var done = !!state.done[index];
            var extra = '';
            if (task.quiz && !done) {
                var wrong = state.quizWrong[index];
                extra = '<div class="bw-quiz">' +
                    '<p class="bw-quiz-q">' + esc(task.quiz.q) + '</p>' +
                    task.quiz.options.map(function (option, optIndex) {
                        return '<button type="button" class="bw-quiz-opt' + (wrong === optIndex ? ' wrong' : '') +
                            '" data-quiz="' + index + '" data-opt="' + optIndex + '">' +
                            '<span class="bw-quiz-key">' + String.fromCharCode(65 + optIndex) + '</span>' +
                            esc(option) + '</button>';
                    }).join('') +
                    (wrong != null ? '<p class="bw-quiz-feedback">Not quite — try again.</p>' : '') +
                '</div>';
            } else if (task.quiz && done) {
                extra = '<div class="bw-quiz-reveal">' +
                    '<p class="bw-quiz-q">' + esc(task.quiz.q) + '</p>' +
                    '<div class="bw-quiz-options">' +
                        task.quiz.options.map(function (option, optIndex) {
                            var right = optIndex === task.quiz.answer;
                            return '<div class="bw-quiz-opt revealed' + (right ? ' correct' : ' muted') + '">' +
                                '<span class="bw-quiz-key">' + String.fromCharCode(65 + optIndex) + '</span>' +
                                esc(option) +
                                (right ? '<span class="bw-quiz-correct-tag">correct</span>' : '') +
                            '</div>';
                        }).join('') +
                    '</div>' +
                    '<p class="bw-quiz-explain">' + esc(task.quiz.explain) + '</p>' +
                '</div>';
            } else if (task.blank && !done) {
                var blankWrong = !!state.blankWrong[index];
                var blankValue = state.blankValues[index] || '';
                extra = '<div class="bw-blank">' +
                    '<p class="bw-blank-q">' + esc(task.blank.q) + '</p>' +
                    '<div class="bw-blank-row">' +
                        '<input type="text" class="bw-blank-input' + (blankWrong ? ' wrong' : '') +
                            '" data-blank-input="' + index + '" value="' + esc(blankValue) +
                            '" placeholder="Type your answer" autocomplete="off" spellcheck="false" aria-label="Fill in the blank answer">' +
                        '<button type="button" class="bw-blank-check" data-blank-check="' + index + '">Check</button>' +
                    '</div>' +
                    '<p class="bw-blank-feedback" data-blank-feedback="' + index + '"' +
                        (blankWrong ? '' : ' hidden') + '>Not quite — try again.</p>' +
                '</div>';
            } else if (task.blank && done) {
                extra = '<div class="bw-blank-reveal">' +
                    '<p class="bw-blank-q">' + esc(task.blank.q) + '</p>' +
                    '<p class="bw-blank-answer">Answer: <strong>' + esc(task.blank.answer) + '</strong></p>' +
                    '<p class="bw-quiz-explain">' + esc(task.blank.explain) + '</p>' +
                '</div>';
            }
            return '<li class="bw-task' + (done ? ' done' : '') + '">' +
                '<span class="bw-tick" aria-hidden="true">' + (done ? tickSvg() : '') + '</span>' +
                '<div class="bw-task-text">' +
                    '<span class="bw-task-label">' + esc(task.text) + '</span>' +
                    extra +
                '</div>' +
            '</li>';
        }).join('');

        var hints = mission.hints || [];
        var hintHtml = '';
        for (var h = 0; h < state.hintsRevealed && h < hints.length; h++) {
            hintHtml += '<p class="bw-hint"><span>HINT ' + (h + 1) + '</span>' + esc(hints[h]) + '</p>';
        }

        var offNote = state.offCapture
            ? '<p class="bw-offnote">This mission expects <code>' + esc(session.expected) + '</code>. Reopen it to continue scoring.</p>'
            : '';

        dock.innerHTML =
            '<div class="bw-dock-top">' +
                '<div class="bw-dock-heading">' +
                    '<p class="bw-dock-kicker">Ch ' + chapter.number + ' · Mission ' +
                        String(session.number).padStart(2, '0') + ' / ' + MISSION_ORDER.length + '</p>' +
                    '<h2 class="bw-dock-title">' + esc(mission.title) + '</h2>' +
                '</div>' +
                '<div class="bw-dock-tools">' +
                    '<button type="button" data-dock-min class="bw-dock-tool" title="Collapse mission panel" aria-label="Collapse">—</button>' +
                    '<button type="button" data-dock-close class="bw-dock-tool" title="Close viewer" aria-label="Close">✕</button>' +
                '</div>' +
            '</div>' +
            '<div class="bw-dock-body">' +
                '<div class="bw-dock-bar"><span style="width:' + pct + '%"></span></div>' +
                '<p class="bw-dock-brief">' + esc(mission.brief) + '</p>' +
                offNote +
                '<ol class="bw-tasks">' + taskHtml + '</ol>' +
                (hintHtml ? '<div class="bw-hints">' + hintHtml + '</div>' : '') +
                '<details class="bw-learn"><summary>Why this works</summary><p>' + esc(mission.learn) + '</p></details>' +
                '<p class="bw-dock-hintnote">Hints cost ' + HINT_COST + ' XP. Wrong answers are free.</p>' +
            '</div>' +
            '<div class="bw-dock-foot">' +
                '<button type="button" class="bw-dock-btn" data-hint' +
                    (state.hintsRevealed >= hints.length ? ' disabled' : '') + '>Hint</button>' +
                '<button type="button" class="bw-dock-btn" data-show>Show me</button>' +
                '<span class="bw-dock-xp">' + mission.xp + ' XP</span>' +
            '</div>';

        if (body) {
            var nextBody = dock.querySelector('.bw-dock-body');
            if (nextBody) nextBody.scrollTop = scroll;
        }
    }

    function onPcapEvent(event) {
        if (!session || !event || !event.detail) return;
        var type = event.detail.type;
        var detail = event.detail.detail || {};

        if (type === 'capture') {
            session.state.captureName = detail.name || '';
            session.state.offCapture = detail.name !== session.expected;
            if (!session.state.offCapture && session.dock) renderDock();
            return;
        }
        if (type === 'closed') {
            setTimeout(function () {
                if (document.querySelector('.pcap-window')) return;
                session = null;
                document.body.classList.remove('academy-running');
                renderHud();
                renderMap();
            }, 0);
            return;
        }
        if (session.state.offCapture) return;

        if (type === 'select') {
            session.state.selections[detail.no] = detail;
        } else if (type === 'filter') {
            if (!detail.error && detail.expr) {
                session.state.filters.push({ expr: detail.expr, matches: detail.matches });
            }
        } else if (type === 'field') {
            session.state.fields.push(detail);
        } else if (type === 'dialog') {
            session.state.dialogs.push(detail.title);
        } else if (type === 'action') {
            session.state.actions.push(detail);
        } else if (type === 'mark') {
            session.state.marked = (detail.nos || []).slice();
        } else {
            return;
        }
        evaluate();
    }

    function boot() {
        els = {
            map: document.getElementById('academyMap'),
            mapSummary: document.getElementById('academyMapSummary'),
            levelName: document.getElementById('hudLevel'),
            xpTotal: document.getElementById('hudXp'),
            xpFill: document.getElementById('xpFill'),
            xpNote: document.getElementById('xpNote'),
            missionCount: document.getElementById('hudMissions'),
            badges: document.getElementById('academyBadges'),
            startBtn: document.getElementById('startTrainingBtn'),
            error: document.getElementById('fileError')
        };

        renderHud();
        renderMap();

        if (els.map) {
            els.map.addEventListener('click', function (e) {
                var button = e.target.closest('[data-mission]');
                if (!button || button.disabled) return;
                startMission(button.getAttribute('data-mission'));
            });
        }

        var startBtn = document.getElementById('startTrainingBtn');
        if (startBtn) {
            startBtn.addEventListener('click', function () {
                var next = nextMissionEntry();
                if (next) startMission(next.mission.id);
                else {
                    document.getElementById('academyMap').scrollIntoView({ behavior: 'smooth', block: 'start' });
                }
            });
        }

        var browseBtn = document.getElementById('browseMissionsBtn');
        if (browseBtn) {
            browseBtn.addEventListener('click', function () {
                var map = document.getElementById('academyMap');
                if (map) map.scrollIntoView({ behavior: 'smooth', block: 'start' });
            });
        }

        var sandboxBtn = document.getElementById('sandboxBtn');
        if (sandboxBtn) {
            sandboxBtn.addEventListener('click', function () {
                var zone = document.getElementById('sandbox');
                if (zone) zone.scrollIntoView({ behavior: 'smooth', block: 'center' });
            });
        }

        document.addEventListener('bw:pcap', onPcapEvent);

        var resetBtn = document.getElementById('resetProgressBtn');
        if (resetBtn) {
            resetBtn.addEventListener('click', function () {
                if (!window.confirm('Reset all academy XP, badges and mission progress?')) return;
                progress = { xp: 0, completed: {} };
                saveProgress();
                renderHud();
                renderMap();
            });
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', boot);
    } else {
        boot();
    }

    window.AcademyGame = {
        start: startMission,
        reset: function () {
            progress = { xp: 0, completed: {} };
            saveProgress();
            renderHud();
            renderMap();
        }
    };
})();
