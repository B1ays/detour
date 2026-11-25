#!/usr/bin/env python3
"""Translations of luci-app-detour, the way LuCI keeps them (gettext):
  - the code holds the English text: _('No internet'), N_(n, '%d server', '%d servers');
  - po/templates/detour.pot is made from the code (as build/i18n-scan.pl does): every message with where it is;
  - po/<lang>/detour.po is the translation - the file a translator edits (by hand, Poedit, Weblate). This script
    brings it in line with the template (as build/i18n-update.pl / msgmerge do): a new message comes in with an
    empty msgstr, a message the code no longer has goes, the translations and the translators' comments stay.
The build (tools/build-feed.sh) compiles po/<lang>/detour.po into detour.<lang>.lmo; LuCI shows the English text of
a message without a translation.

It stops on: a Russian message left untranslated (an interface string cannot slip into a release in English), a
translation whose placeholders (%s, %d...) differ from the English, a msgid with a leading or trailing space (LuCI
does not find those). Other languages may have gaps: those show in English.
The daemon's messages (notifications) are a dictionary below (RU_NOTIFY) -> packages/detour/.../i18n/ru.json.

usage: i18n.py <luci-app-detour dir>   (the detour package is its sibling)"""
import json, os, re, sys, importlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
extract_mod = importlib.import_module('i18n-extract')

COMPLETE = [ 'ru' ]     # languages that must have every message translated
ph = lambda s: sorted(re.findall(r'%[-0-9.]*[sdf%]', s))

# ---- po files ----
def unq(s):
	s = s.strip()
	assert s[0] == '"' and s[-1] == '"', s
	s = s[1:-1]; out = []; i = 0
	while i < len(s):
		if s[i] == '\\':
			out.append({'n': '\n', 't': '\t', '"': '"', '\\': '\\'}.get(s[i + 1], s[i + 1])); i += 2
		else:
			out.append(s[i]); i += 1
	return ''.join(out)

def q(s):
	return '"' + s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\t', '\\t') + '"'

def read_po(path):
	"""-> (header text, [entry]); entry: {id, plural, str: [..], comments: ['# ...'], flags: ['fuzzy']}"""
	entries, cur, field = [], None, None
	header = None
	def done():
		nonlocal cur, header
		if cur is None: return
		if cur['id'] == '' and cur['plural'] is None: header = cur['str'][0]
		else: entries.append(cur)
		cur = None
	def new():
		nonlocal cur
		if cur is None or 'id' in cur and cur.get('_started'):
			done(); cur = { 'id': None, 'plural': None, 'str': [], 'comments': [], 'flags': [] }
		return cur
	pending_c, pending_f = [], []
	for line in open(path, encoding='utf-8').read().split('\n'):
		if not line.strip():
			done(); field = None; continue
		if line.startswith('#~'): continue                      # obsolete: dropped
		if line.startswith('#,'): pending_f += [ x.strip() for x in line[2:].split(',') if x.strip() ]; continue
		if line.startswith('#:') or line.startswith('#.'): continue   # references: made anew from the code
		if line.startswith('#'): pending_c.append(line); continue
		m = re.match(r'^(msgid_plural|msgid|msgstr(?:\[(\d+)\])?)\s+(".*")$', line)
		if m:
			if m.group(1) == 'msgid':
				done(); cur = { 'id': unq(m.group(3)), 'plural': None, 'str': [], 'comments': pending_c, 'flags': pending_f }
				pending_c, pending_f = [], []; field = ('id',)
			elif m.group(1) == 'msgid_plural':
				cur['plural'] = unq(m.group(3)); field = ('plural',)
			else:
				i = int(m.group(2)) if m.group(2) else 0
				while len(cur['str']) <= i: cur['str'].append('')
				cur['str'][i] = unq(m.group(3)); field = ('str', i)
			continue
		if line.startswith('"') and cur is not None and field:
			v = unq(line)
			if field[0] == 'str': cur['str'][field[1]] += v
			else: cur[field[0]] += v
			continue
		sys.exit('%s: cannot read the line %r' % (path, line))
	done()
	return header, entries

def write_entries(out, e, refs, nplurals):
	out += e.get('comments', [])
	if refs: out.append('#: ' + ' '.join(refs))
	if e.get('flags'): out.append('#, ' + ', '.join(e['flags']))
	out.append('msgid ' + q(e['id']))
	if e['plural'] is not None:
		out.append('msgid_plural ' + q(e['plural']))
		st = (e.get('str') or []) + [ '' ] * nplurals
		for i in range(nplurals): out.append('msgstr[%d] %s' % (i, q(st[i])))
	else:
		out.append('msgstr ' + q((e.get('str') or [ '' ])[0]))
	out.append('')

def write_pot(app, msgs):
	out = [ 'msgid ""', 'msgstr "Content-Type: text/plain; charset=UTF-8"', '' ]
	for m in msgs: write_entries(out, { 'id': m['id'], 'plural': m['plural'] }, m['refs'], 2)
	d = os.path.join(app, 'po', 'templates'); os.makedirs(d, exist_ok=True)
	open(os.path.join(d, 'detour.pot'), 'w', encoding='utf-8', newline='\n').write('\n'.join(out))
	print('template: %d messages -> %s' % (len(msgs), os.path.join(d, 'detour.pot')))

def update_po(app, lang, msgs):
	path = os.path.join(app, 'po', lang, 'detour.po')
	header, entries = read_po(path)
	if header is None: sys.exit('%s: no header' % path)
	m = re.search(r'nplurals=(\d+)', header)
	if not m: sys.exit('%s: no Plural-Forms in the header' % path)
	nplurals = int(m.group(1))
	have = { (e['id'], e['plural']): e for e in entries }
	out = [ 'msgid ""', 'msgstr ""' ] + [ q(l + '\n') for l in header.split('\n') if l ] + [ '' ]
	errs, missing = [], []
	for msg in msgs:
		k = (msg['id'], msg['plural'])
		e = have.pop(k, None) or { 'id': msg['id'], 'plural': msg['plural'], 'str': [], 'comments': [], 'flags': [] }
		write_entries(out, e, msg['refs'], nplurals)
		strs = [ s for s in (e['str'] or []) ]
		if not any(strs) or (msg['plural'] is not None and (len(strs) < nplurals or not all(strs[:nplurals]))) or 'fuzzy' in e['flags']:
			missing.append(msg['id']); continue
		want = ph(msg['plural'] if msg['plural'] is not None else msg['id'])
		for s in strs[:nplurals] if msg['plural'] is not None else strs[:1]:
			if ph(s) != want: errs.append('%s: %r - its placeholders differ from the English' % (lang, msg['id']))
	open(path, 'w', encoding='utf-8', newline='\n').write('\n'.join(out))
	gone = len(have)
	print('%s: %d messages, %d untranslated%s -> %s' % (lang, len(msgs), len(missing), (', %d no longer in the code removed' % gone) if gone else '', path))
	if lang in COMPLETE and missing:
		errs.append('%s: untranslated (fill msgstr in %s):\n    %s' % (lang, path, '\n    '.join(missing)))
	return errs

# the messages the router sends to people (detourd, watch.uc, notify.uc) -> detour/root/usr/share/detour/i18n/ru.json
RU_NOTIFY = {
	' (all lists may take %s MB, they take %s MB)': ' (всем спискам можно занять %s МБ, они занимают %s МБ)',
	' (%s MB of memory free, %s MB of it must stay free)': ' (свободно %s МБ памяти, из них %s МБ должны оставаться свободными)',
	' (%s MB of memory free)': ' (свободно %s МБ памяти)',
	'Policy %s: no exit works, its traffic goes directly (as set up)': 'Политика %s: не работает ни один выход, её трафик пошёл напрямую (так настроено)',
	'Policy %s: no exit works, its traffic is blocked': 'Политика %s: не работает ни один выход, её трафик заблокирован',
	'Policy %s has no exits left, its traffic is blocked': 'Политика %s осталась без выходов, её трафик заблокирован',
	'Policy %s goes through the exits again (it went directly for %s)': 'Политика %s снова идёт через выходы (шла напрямую %s)',
	'Policy %s works again (it was blocked for %s)': 'Политика %s снова работает (была заблокирована %s)',
	'Policy %s switched: %s → %s': 'Политика %s переключилась: %s → %s',
	'Exit %s works again (it did not answer for %s)': 'Выход %s снова работает (не отвечал %s)',
	"the server's address seems blocked by the provider: no answer directly, an answer through another exit": 'адрес сервера, похоже, заблокирован провайдером: напрямую не отвечает, а через другой выход отвечает',
	'the server answers neither directly nor through another exit': 'сервер не отвечает ни напрямую, ни через другой выход',
	'the server does not answer': 'сервер не отвечает',
	'the server answers, the protocol itself does not work (keys, settings or the provider filtering the content)': 'сервер отвечает, не работает сам протокол (ключи, настройки или фильтр провайдера по содержимому)',
	"the server's name is not found in DNS": 'имя сервера не находится в DNS',
	'the engine did not start: its tunnel device is missing': 'движок не запустился: нет его туннельного устройства',
	'the engine cannot make its tunnel: the kernel module kmod-tun is missing': 'движок не может создать туннель: нет модуля ядра kmod-tun',
	'Exit %s stopped answering': 'Выход %s перестал отвечать',
	'WARP %s moved to the Cloudflare point %s (it was %s)': 'WARP %s перешёл на точку Cloudflare %s (была %s)',
	'no answer': 'без ответа',
	'(at %s)': '(в %s)',
	'Test message: notifications work': 'Проверочное сообщение: уведомления работают',
	'"%s"': '«%s»',
	'%d s': '%d с',
	'%d min': '%d мин',
	'%d h %d min': '%d ч %d мин',
	'%.1f GB': '%.1f ГБ',
	'(addresses)': '(адреса)',
	'could not download from %s': 'не удалось скачать с %s',
	'could not download the v2fly category %s': 'не удалось скачать категорию v2fly %s',
	'only %s entries came (at least %s needed)': 'пришло только %s записей (нужно не меньше %s)',
	'no file %s': 'нет файла %s',
	'its policy %s is gone': 'его политики %s больше нет',
	'not enough router memory: ~%s MB more needed, %s MB left for lists': 'не хватает памяти роутера: нужно ещё ~%s МБ, для списков осталось %s МБ',
	'the download is bigger than the memory holds (over %s MB)': 'скачанное больше, чем помещается в память (больше %s МБ)',
	'the provider did not answer': 'провайдер не ответил',
	'no suitable servers in the answer': 'в ответе нет подходящих серверов',
	'the engine chosen for it is not installed': 'выбранный для неё движок не установлен',
	'wrong subscription address': 'неверный адрес подписки',
	'the subscription address points into the local network': 'адрес подписки указывает во внутреннюю сеть',
	"The provider's internet is back (it was gone for %s)": 'Интернет у провайдера вернулся (не было %s)',
	"The provider's internet is gone. Messages about the exits wait until it is back": 'Пропал интернет у провайдера. Сообщения о выходах подождут его возвращения',
	'The router rebooted, Detour works: %d of %d exits work': 'Роутер перезагрузился, Detour работает: выходов работает %d из %d',
	'Did not come up: %s': 'Не поднялись: %s',
	'The list %s did not update: %s. %s': 'Список %s не обновился: %s. %s',
	'The previous one works (entries: %d)': 'Работает прежний (записей: %d)',
	'There is no previous one, the list is empty for now': 'Прежнего нет, список пока пуст',
	'The subscription %s did not update: %s. The previous servers stay': 'Подписка %s не обновилась: %s. Остались прежние серверы',
	'The subscription %s ends on %s': 'Подписка %s заканчивается %s',
	'The subscription %s ended on %s': 'Подписка %s закончилась %s',
	'The subscription %s: %d%% of the traffic used (%s of %s)': 'Подписка %s: израсходовано %d%% трафика (%s из %s)',
}

def write_notify(detour):
	"""the daemon's dictionary; a message without a translation stops the script, as in LuCI"""
	msgs = extract_mod.extract_ucode(detour)
	missing = [ m['id'] for m in msgs if m['id'] not in RU_NOTIFY ]
	if missing:
		sys.exit('untranslated (RU_NOTIFY):\n  ' + '\n  '.join(missing))
	# a placeholder dropped or added in a translation would break sprintf
	bad = [ m['id'] for m in msgs if ph(m['id']) != ph(RU_NOTIFY[m['id']]) ]
	if bad:
		sys.exit('placeholders differ:\n  ' + '\n  '.join(bad))
	d = os.path.join(detour, 'root', 'usr', 'share', 'detour', 'i18n'); os.makedirs(d, exist_ok=True)
	out = { m['id']: RU_NOTIFY[m['id']] for m in msgs }
	open(os.path.join(d, 'ru.json'), 'w', encoding='utf-8', newline='\n').write(json.dumps(out, ensure_ascii=False, indent='\t', sort_keys=True) + '\n')
	print('notifications: %d messages -> %s' % (len(out), os.path.join(d, 'ru.json')))

def main(app):
	msgs = sorted(extract_mod.extract(app), key=lambda m: (m['id'], m['plural'] or ''))   # sorted, as i18n-scan.pl
	# po2lmo/LuCI do not find a message whose msgid starts or ends with a space: write _('Name:') + ' '
	edged = [ m['id'] for m in msgs if m['id'] != m['id'].strip() and m['id'].strip() ]
	if edged:
		sys.exit('messages with a leading/trailing space (they would stay untranslated):\n  ' + '\n  '.join(repr(x) for x in edged))
	write_pot(app, msgs)
	errs = []
	podir = os.path.join(app, 'po')
	for lang in sorted(os.listdir(podir)):
		if lang != 'templates' and os.path.isfile(os.path.join(podir, lang, 'detour.po')):
			errs += update_po(app, lang, msgs)
	if errs: sys.exit('\n'.join(errs))

if __name__ == '__main__':
	sys.stdout.reconfigure(encoding='utf-8'); sys.stderr.reconfigure(encoding='utf-8')
	main(sys.argv[1])
	write_notify(os.path.join(os.path.dirname(os.path.abspath(sys.argv[1])), 'detour'))
