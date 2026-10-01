# SPDX-License-Identifier: AGPL-3.0-or-later
# Candor source web UI (Tier W), English master catalog.
# Spec keys `sui.a.b` are Fluent ids `sui-a-b` (Fluent ids cannot contain dots).
# Class comments: `@class tier0` = sec:critical tier0; `@class critical` = sec:critical; none = ui.
# `**text**` marks bold; it is applied after HTML escaping.

## Layout

sui-lang-name = English
sui-title = { $mode } · { $step } · { $org } secure reporting
sui-title-error = Error: { $title }
sui-skip = Skip to main content
sui-footer-nav = Help and safety
sui-footer-help = Help & safety guide
sui-footer-protect = How this site protects you
sui-footer-language = Language
sui-footer-leave = Leave
sui-header-org = { $org }
sui-as-listed = (as listed by this site)
sui-as-reported = (as reported by this site)
sui-date-utc = { $date } (UTC)
sui-required = (required)
sui-optional = (optional)
sui-none = None
sui-list-sep = ,{" "}
sui-btn-continue = Continue
sui-btn-back = Back
sui-btn-save-continue = Save and continue

## Progress (11 §5.8)

sui-step-label = Step { $n } of { $total }: { $name }
sui-step-nav = Report steps
sui-step-done = (done)
sui-step-1 = Start
sui-step-2 = Who should not see it
sui-step-3 = What is this about
sui-step-4 = What happened
sui-step-5 = Who is involved
sui-step-6 = More details
sui-step-7 = Add files
sui-step-8 = Check and send

## Mode banner (11 §5.2; generated from 03 §7)

sui-mode-region = Protection mode
# @class tier0
sui-mode-word-anonymous = ANONYMOUS
# @class tier0
sui-mode-word-confidential = CONFIDENTIAL
# @class tier0
sui-mode-word-identified = IDENTIFIED
# @class tier0
sui-mode-word-clearnet = NOT ANONYMOUS
# @class tier0
sui-mode-anonymous = **ANONYMOUS** — Candor does not collect who you are. Your writing and files can still identify you.
# @class tier0
sui-mode-confidential = **CONFIDENTIAL — NOT ANONYMOUS** — You told us who you are. Your name is locked so that only { $custodian } can open it, with a recorded reason. The people handling your report can read everything else you write.
# @class tier0
sui-mode-confidential-seen = **CONFIDENTIAL — NOT ANONYMOUS** — The people handling your report have read a message that said who you are.
# @class tier0
sui-mode-cue-seen = Case team knows.
# @class tier0
sui-mode-identified = **IDENTIFIED — NOT ANONYMOUS** — Your name will be shown to the people handling your report.
# @class tier0
sui-mode-clearnet = **NOT ANONYMOUS** — This website can see your internet address. To report anonymously, use Tor Browser: { $onion }
# @class tier0
sui-tier-w = Web mode: encrypted on arrival.
sui-tier-w-options = What are my options?

## Warning banners (11 §5.2.1)

sui-wb-region = Warnings
# @class tier0
sui-wb-operator = Warning: this service's regular public statement (that it has not been secretly changed or ordered to watch users) is missing or out of date. Last statement: { $last }. This may be harmless, or it may mean the service is under legal pressure. If you are at higher risk, don't use this website. Use the Candor app, or wait.
# @class tier0
sui-wb-operator-none = none
# @class tier0
sui-wb-incident = Notice: the operator has declared a security incident affecting this site, dated { $date }. What you type on this website may have been exposed during the incident.
sui-wb-incident-link = Read the notice
# @class tier0
sui-wb-capture = Security notice. On { $day } the operator made an incident-response recording of the submission server's memory or network traffic, approved by { $approver }. If you used the website (no-JavaScript) version on that day, what you typed and your passphrase may be included in that recording. Consider changing your passphrase. The Candor Source App encrypts on your device.
# @class tier0
sui-wb-roster = The list of people who receive reports in { $channel } is changing on { $date } (as listed by this site).
sui-wb-roster-link = See the change

## Honesty statements (ADR-004, ADR-035 §5, ADR-039)

# @class tier0
sui-tier-w-honesty = If the intake server is compromised or legally compelled while you use the website (no-JavaScript) version, what you type, and your passphrase when you log in, can be captured. For the highest risk, use the Candor Source App.
# @class tier0
sui-login-honesty = On this website your passphrase is checked on the server. A compromised or compelled server could capture it and note when you sign in. The Candor app checks for replies without telling the server which mailbox is yours.
# @class tier0
sui-passphrase-honesty = Anyone with your passphrase can read your replies and write as you. Each time you sign in, a compromised server could note the exact time.

## JavaScript warning (05 §8.2)

# @class critical
sui-js-warning = JavaScript is on. Set Tor Browser to "Safest": click the shield icon, then Settings, and choose Safest. Then reload this page.
# @class critical
sui-js-check = Check: is Tor Browser set to "Safest"?

## Session (11 §5.6)

# @class critical
sui-session-rule = For your safety, this session ends after 20 minutes without activity, and always after 2 hours.
# @class critical
sui-session-idle-warn = You will be signed out in about 5 minutes for your safety.
# @class critical
sui-session-abs-warn = This session ends in about 10 minutes. Anything you have not sent will be lost.
sui-session-stay = Stay
# @class critical
sui-draft-limits = Your draft is kept only in the server's memory while this Tor Browser window stays open, for at most 2 hours. It is lost if you close the window, stop for 20 minutes, or the server restarts. Nothing is sent until you choose Send.

## Errors (11 §5.7)

sui-error-summary = There is a problem
# @class critical
sui-error-kept = Your text is kept for now. It is lost if you close Tor Browser or after the session ends.
# @class critical
sui-error-not-sent = Your report was not sent. Try again.

## S01 Landing

sui-landing-step = Welcome
sui-landing-h1 = { $org } secure reporting
sui-landing-before = Before you start
# @class critical
sui-landing-b1 = Don't use a work computer, work phone or work network.
# @class critical
sui-landing-b2 = Use Tor Browser set to "Safest".
# @class critical
sui-landing-b3 = In Tor Browser, this site can't see your internet address, but it can't protect a computer or phone that your employer watches.
sui-landing-start = Start a new report
sui-landing-return = I have a passphrase
sui-landing-guide = Read the safety guide
sui-landing-protect = How this site protects you
# @class critical
sui-landing-recovery = A backup key held by { $holders } can unlock reports ({ $k } of them together).
# @class critical
sui-landing-reduced-sod = This organization runs this service with reduced separation of duties.
# @class critical
sui-landing-alternative = Can't use Tor Browser? { $alt } — this is NOT ANONYMOUS.

## S02 Safety Check

sui-safety-step = Safety check
sui-safety-h1 = Check these things first
sui-safety-essentials = The basic steps
sui-safety-cards = Safety guide
sui-safety-leave = Leave now

## S03 Anonymity Status

sui-status-step = How this site protects you
sui-status-h1 = How this site protects you
sui-status-connection = Connection
# @class critical
sui-status-connection-dd = Through Tor (onion address). In Tor Browser, this site cannot see your internet address.
sui-status-address = Check the address
# @class critical
sui-status-address-dd = It should match the address on { $info } or on printed material from { $org }. If it doesn't, leave.
sui-status-browser = Browser security
# @class critical
sui-status-js-off = JavaScript is off ✓
# @class critical
sui-status-js-on = JavaScript is on: set Safest
sui-status-mode = Mode
# @class tier0
sui-status-mode-anonymous = ANONYMOUS: Candor does not collect who you are. Your writing and files can still identify you.
# @class tier0
sui-status-mode-confidential = CONFIDENTIAL, NOT ANONYMOUS: your name is locked for { $custodian }.
# @class tier0
sui-status-mode-identified = IDENTIFIED, NOT ANONYMOUS: the people handling your report will see your name.
# @class tier0
sui-status-mode-clearnet = NOT ANONYMOUS: this website can see your internet address.
sui-status-protection = How your report is protected
# @class tier0
sui-status-protection-dd = Your report is locked (encrypted) on our server as soon as it arrives. A live-compromised intake server could read what you submit while it is being encrypted.
sui-high-summary = If you are at higher risk
# @class critical
sui-status-pq = Tor's connection encryption does not yet resist future quantum computers. Someone who records traffic today might read website reports in the future. The Candor app encrypts your report on your device in a way designed to resist this.
sui-status-replies = Replies on this website
# @class critical
sui-status-replies-dd = When you sign in on this website, the server looks up your mailbox. A compromised server could note when you sign in and read your replies.
sui-status-first = Who first reads your report
sui-status-first-channel = { $channel }: { $roles }
sui-status-later = Who may read it later
# @class critical
sui-status-later-dd = The first readers may ask other team members to help: { $roles } (as listed by this site). They cannot give access to anyone you tick.
sui-status-kept = People kept out
# @class critical
sui-status-kept-dd = On the next pages you can tick roles your report is about. They will not get a key to open it.
sui-status-changes = Recent changes to recipients
sui-status-change-item = { $channel }: changes on { $date }
sui-status-operator = Operator statement
# @class critical
sui-status-operator-signal = A statement like this is a signal, not a guarantee. It can be missing for harmless reasons, and people can be forced to publish it.
sui-status-sod = Separation of duties
# @class critical
sui-status-sod-dd = This organization has few staff for this service. An outside party ({ $label }) oversees it, but fewer people check each other than usual.
sui-status-backup = Backup key
sui-status-what = What protects you and what does not
sui-status-checking = Checking this site
# @class tier0
sui-status-noverify = Checking these values does not protect a report sent from this website; only the Candor app checks them before encrypting.
# @class critical
sui-status-app = Get the Candor app in Tor Browser from the Candor project's address: { $address }
# @class critical
sui-status-app-settings = The app's own settings show the key fingerprints and log checks.
sui-status-onion-label = Onion address: { $address }

## S04 Create Report

sui-new-h1 = Start your report
sui-new-channel-legend = Who should receive your report?
sui-new-channel-langs = Languages: { $langs }
sui-new-channel-first = First read by: { $roles }
# @class critical
sui-new-channel-unavailable = This channel can't accept reports right now. Choose another channel, or try again later.
sui-new-channel-independent = Channels that are independent:
# @class critical
sui-channel-stale = This channel is temporarily unavailable. Try again later.
sui-new-mode-legend = Do you want to tell us who you are?
# @class tier0
sui-new-mode-anon = No, stay anonymous (recommended)
# @class tier0
sui-new-mode-anon-consequence = Candor does not collect who you are. Your writing and files can still identify you.
# @class tier0
sui-new-mode-conf = Yes, but keep my name confidential
# @class tier0
sui-mode-conf-consequence = Your name is locked. Only { $custodian } can open it, with a recorded reason and two approvals. They work for { $org }. A court or regulator can require them to reveal your name. You will normally be told if that happens, but telling you can be delayed. The people handling your report can read everything else you write.
# @class tier0
sui-new-mode-ident = Yes, show my name to the people handling it
# @class tier0
sui-new-mode-ident-consequence = The people handling your report will be told your name. Tor Browser still hides your internet address, but you are not anonymous to the organization.
sui-new-err-channel = Choose who should receive your report.
sui-new-err-mode = This channel does not accept confidential reports; choose another option.

## S04b Concerns (ADR-030, ADR-037)

sui-concerns-h1 = Is your report about any of these people?
sui-concerns-first = Your report is first read by: { $roles }.
# @class tier0
sui-concerns-explain = Tick anyone your report is about, or anyone who should not see it. They will not get a key to open your report, now or later. You don't have to tick anything.
# @class tier0
sui-concerns-who-sees = Your answers are encrypted and seen only by the independent triage team, who use them to keep the people involved away from your report. They may still suggest what your report is about.
# @class critical
sui-concerns-team-hint = If you tick your own manager, the triage team will know which team you work in.
# @class critical
sui-concerns-auto = Your organization may also automatically keep out people linked to the type of report you choose. You will see the final list before you send.
# @class critical
sui-concerns-err-load = We couldn't load the list of roles for this channel. Try again later.

## S04b-X

# @class tier0
sui-nox-h1 = No one left to read your report first
# @class tier0
sui-nox-text = If these roles are kept out, no one in this channel's first-reading team could open your report. Please use a channel that is independent of them.
sui-nox-external = You can also contact:
sui-nox-choose = Choose another channel
sui-nox-change = Change who is kept out

## S05 Questionnaire

sui-q-category = What is this about?
sui-q-category-other = Other
sui-q-what = What happened?
sui-q-what-hint = Say what happened and where evidence can be found.
sui-q-when = About when?
# @class critical
sui-q-when-hint = Use general dates if an exact date could point to you.
sui-q-month = Month
sui-q-year = Year
sui-q-month-none = Choose a month
sui-q-year-none = Choose a year
sui-q-ongoing = It is still happening
sui-q-unsure = Not sure
sui-q-where = Where?
sui-q-where-hint = A general place, for example "Finance department, head office".
sui-q-who = Who is involved?
sui-q-who-hint = Names or roles.
sui-q-how = How do you know?
sui-q-how-saw = I saw it
sui-q-how-told = I was told
sui-q-how-documents = I have documents
sui-q-how-other = Other
sui-q-people = About how many people could know the facts in your report?
# @class critical
sui-q-people-hint = This helps the team avoid actions that could point to you.
sui-q-people-few = 1–5
sui-q-people-some = 6–20
sui-q-people-many = More than 20
sui-q-people-unsure = Not sure
sui-q-before = Has this been reported before?
sui-q-else = Anything else?
sui-yn-yes = Yes
sui-yn-no = No
sui-yn-unsure = Not sure
# @class critical
sui-q-ai = Keep it short and factual. Don't paste into AI tools, translators or grammar checkers.
sui-q-maxlen = Up to { $max } characters.
sui-q-details = What details could point to me?
sui-q-err-what = Tell us what happened. This is the only question you must answer.
sui-q-err-required = Answer this question.
sui-q-err-too-long = This answer is too long. The limit is { $max } characters.
sui-q-err-future = The date can't be in the future.
sui-q-err-choice = Choose one of the options.
sui-month-1 = January
sui-month-2 = February
sui-month-3 = March
sui-month-4 = April
sui-month-5 = May
sui-month-6 = June
sui-month-7 = July
sui-month-8 = August
sui-month-9 = September
sui-month-10 = October
sui-month-11 = November
sui-month-12 = December

## S05b Identity disclosure

sui-id-step = Your name
# @class tier0
sui-id-h1 = Tell us who you are
# @class tier0
sui-id-explain = Your name is locked separately. Only { $custodian } can unlock it, with a recorded reason and two approvals.
sui-id-name = Full name
sui-id-role = Role or department (optional)
sui-id-contact = How can the team contact you?
sui-id-contact-mailbox = Only through this secure mailbox (recommended)
sui-id-contact-other = Also by another way
sui-id-contact-other-label = Another way to contact you
# @class critical
sui-id-contact-warning = The team should never need to move the conversation to email, phone or chat. Another way to contact you can be seen by other people, and it can point to you.
sui-id-err-name = Enter your name, or go back and choose to stay anonymous.
sui-id-err-too-long = This is too long. The limit is { $max } characters.
# @class tier0
sui-id-confirm-h1 = You are about to stop being anonymous
# @class tier0
sui-id-confirm-conf = After this your report is CONFIDENTIAL, NOT ANONYMOUS. Your identity will be locked so that only { $custodian } can open it, and only with a legal reason. They work for { $org }. A court or regulator can require them to reveal your name. If they do, you will normally be told, but this can be delayed. The people handling your report can still read what you write.
# @class tier0
sui-id-confirm-ident = After this your report is IDENTIFIED, NOT ANONYMOUS. Your name will be shown to the people handling your report. It is also kept locked for { $custodian }. Tor Browser still hides your internet address, but you are no longer anonymous to the organization.
# @class tier0
sui-id-confirm-yes = Yes, share who I am
# @class tier0
sui-id-confirm-no = No, stay anonymous
# @class tier0
sui-mode-changed-conf = Your report is now CONFIDENTIAL
# @class tier0
sui-mode-changed-ident = Your report is now IDENTIFIED
# @class tier0
sui-mode-changed-text = The banner at the top of every page now shows this. Before you send, you can still remove your name on the "Check and send" page. After you send, this cannot be undone.

## S06 Attach Evidence

sui-files-h1 = Add files (optional)
# @class critical
sui-files-describe = Describe or retype when you can. Files can hold hidden information.
sui-files-limits = You can add up to { $max_files } files, up to { $max_file } each, { $max_total } in total.
# @class critical
sui-files-time = Large files can take many minutes over Tor. Keep this page open. If the upload stops, you need to upload that file again.
# @class critical
sui-files-size-visible = Someone watching your internet connection and this site's connection at the same time can recognise a large upload by its size and time. For large or many files, the Candor app is safer, or describe the content in words.
sui-files-input = Choose a file
sui-files-one = Add one file at a time.
# @class critical
sui-files-neutral = Replace file names with plain names (recommended)
sui-files-upload = Upload
sui-files-caption = Files added to this report
sui-files-col-name = File
sui-files-col-size = Size
sui-files-col-describe = Description
sui-files-col-remove = Remove
sui-files-size = { $size }
sui-files-describe-label = Describe { $name } (optional)
sui-files-remove = Remove { $name }
sui-files-none = No files added yet.
sui-files-err-too-large = This file is too large. The limit is { $max_file } per file and { $max_total } in total.
sui-files-err-stopped = The upload stopped. Please try again. Files already listed are kept for this session.
sui-files-err-empty = This file is empty. Choose another file.
sui-files-err-count = You can add up to { $max_files } files.
sui-size-mb = { $n } MB
sui-size-gb = { $n } GB
sui-size-small = less than 1 MB

## S07 Metadata Warning (05 §7.2)

# @class critical
sui-meta-h1 = Before you send these files
# @class critical
sui-meta-honest = On this website, we can't remove hidden data before your file is locked. The team normally views a cleaned copy, but your original file is kept as evidence.
sui-meta-caption = What each file may reveal
sui-meta-col-file = File
sui-meta-col-type = Type
sui-meta-col-risks = What it may reveal
sui-class-photo = Photo
sui-class-screenshot = Screenshot
sui-class-office = Office document
sui-class-pdf = PDF
sui-class-scan = Scan
sui-class-av = Audio or video
sui-class-archive = Archive
sui-class-email = Email
sui-class-other = Other file
# @class critical
sui-risk-photo-location = The exact location, time and camera or phone model.
# @class critical
sui-risk-photo-background = What is in the background: desk, hands, reflections, badges.
# @class critical
sui-risk-photo-camera = Experts can sometimes match a photo to the camera that took it.
# @class critical
sui-risk-screenshot = Your user name, open tabs, pop-up messages and the time.
# @class critical
sui-risk-office-meta = Author, company, user name, folder names, comments, tracked changes and older versions.
# @class critical
sui-risk-office-canary = Small differences between copies can show whose copy it was.
# @class critical
sui-risk-pdf-meta = Author, software, older versions inside, scanner or printer data.
# @class critical
sui-risk-pdf-dots = Printer dots in scanned pages.
# @class critical
sui-risk-scan = If this is a scan or photo of paper: printer dots.
# @class critical
sui-risk-av-meta = Location, device and date.
# @class critical
sui-risk-av-voices = Voices and background sounds can identify people.
# @class critical
sui-risk-archive = Names, dates and user names of every file inside.
# @class critical
sui-risk-email = Full headers: names, addresses, servers, times and the forwarding chain.
# @class critical
sui-risk-other = Files can hold hidden information about who made them.
sui-meta-also = Also:
# @class critical
sui-meta-also-canary = Unique copies ("canary traps"): if only a few people had a document, describe it instead.
# @class critical
sui-meta-also-watermark = Invisible marks in documents, images and work screens.
# @class critical
sui-meta-also-dots = Printer tracking dots on photos and scans of printed pages.
sui-meta-change = Change files
sui-meta-continue = Continue with these files

## S08 Review

sui-review-h1 = Check your report before you send it
# @class tier0
sui-review-mode-anonymous = Your report will be sent ANONYMOUSLY.
# @class tier0
sui-review-mode-confidential = Your report will be sent CONFIDENTIALLY: NOT ANONYMOUS, with your name locked.
# @class tier0
sui-review-mode-identified = Your report will be sent WITH YOUR NAME: NOT ANONYMOUS.
sui-review-change = Change
sui-review-recipients = Who gets your report
sui-review-channel = Channel
sui-review-first = First read by
sui-review-others = Others the first readers may ask to help
sui-review-kept = Kept out
# @class critical
sui-review-kept-auto = { $n ->
    [one] and 1 role kept out automatically by your organization's conflict-of-interest rules
   *[other] and { $n } roles kept out automatically by your organization's conflict-of-interest rules
}
sui-review-answers = Your answers
sui-review-edit = Edit: { $question }
sui-review-no-answer = (no answer)
sui-review-files = Files
sui-review-edit-files = Edit: Files
sui-review-file-item = { $name } ({ $class })
sui-review-hints-h2 = Check for details that could point to you
# @class critical
sui-review-hint = Your text may contain details that point to you: { $kind } in "{ $field }", line { $line }.
# @class critical
sui-review-no-hints = We found nothing obvious. This check is a reminder, not a protection.
sui-hint-email = an email address
sui-hint-phone = a phone number
sui-hint-url = a web address
sui-hint-handle = an @name
sui-hint-pattern = an ID number
sui-hint-phrase = a phrase about yourself
sui-hint-signoff = a sign-off line
# @class critical
sui-review-invisible = { $n ->
    [one] Your text contains 1 invisible or look-alike character. It can act as a hidden signature from the document you copied.
   *[other] Your text contains { $n } invisible or look-alike characters. They can act as a hidden signature from the document you copied.
}
sui-review-invisible-remove = Remove them
sui-review-invisible-keep = Keep them
sui-review-style-h2 = Your writing style
# @class critical
sui-review-style-1 = Short and factual.
# @class critical
sui-review-style-2 = No greetings, sign-offs or jokes.
# @class critical
sui-review-style-3 = None of your usual phrases, spelling habits or emojis.
# @class critical
sui-review-style-4 = Not rewritten with online AI tools.
sui-review-identity-h2 = Your name
# @class tier0
sui-review-identity-remove = Remove my name and stay anonymous
sui-delivery-legend = When should the team receive it?
# @class critical
sui-delivery-now = At the next scheduled pickup
# @class critical
sui-delivery-delay = After a random delay of 1 to 3 days
# @class critical
sui-delivery-help = A delay makes it harder to connect the time your report arrives with what you did at work. The team's deadlines start when they receive it.
sui-review-send = Continue to send
sui-review-discard = Discard this report
sui-review-err-missing = Some required answers are missing.

## S10 Recovery Credential

sui-cred-step = Save your passphrase
# @class tier0
sui-cred-h1 = Save your passphrase before you send
# @class tier0
sui-cred-not-sent = Your report has not been sent yet.
sui-cred-h2 = Your passphrase
# @class tier0
sui-cred-all-or-none = Write down all the words or none. A partly written passphrase is easier to guess.
sui-cred-oneline = All { $n } words on one line, to copy
# @class tier0
sui-cred-copy-warning = If you copy it, some computers and phones keep or sync what you copy. Clear it afterwards.
sui-cred-spell = Spell out each word
# @class tier0
sui-cred-next-info = On the next page you will type 3 of these words to show you have kept them. This page will not be shown again.
sui-cred-next = Next: check my passphrase
# @class tier0
sui-rot-cred-h1 = Save your new passphrase
# @class tier0
sui-rot-cred-old = Your old passphrase still works until you finish. After you confirm the new one, only the new one works.

## S10c Confirm and send

sui-confirm-step = Confirm and send
# @class tier0
sui-confirm-h1 = Type 3 words from your passphrase
sui-confirm-word = Word { $p }
# @class tier0
sui-send-anonymous = Send anonymously
# @class tier0
sui-send-confidential = Send confidentially (with my name)
# @class tier0
sui-send-identified = Send with my name
# @class tier0
sui-confirm-note = If you don't see the page "Your report was sent" after this, open your mailbox with your passphrase. If it opens, your report was sent.
sui-confirm-new = Get a new passphrase
# @class tier0
sui-confirm-mismatch = One or more words don't match. Check your saved passphrase. If you didn't keep it, choose Get a new passphrase.
# @class tier0
sui-confirm-exhausted = The words did not match 3 times. Get a new passphrase, or discard this report. Nothing has been sent.
sui-rot-confirm-btn = Change my passphrase

## S10s Report sent

sui-sent-step = Report sent
sui-sent-h1 = Your report was sent
sui-sent-date = Sent: { $date } (UTC).
# @class critical
sui-sent-delayed = It will reach the team after a random delay of 1 to 3 days.
sui-sent-next = What happens next: the team aims to confirm receipt within { $days } days of receiving it.
sui-sent-mailbox = Use your passphrase to open your mailbox later.
sui-sent-open = Open my mailbox

## S11 Login and inbox

sui-login-step = Open your mailbox
sui-login-h1 = Open your mailbox
# @class critical
sui-login-reminder = Tor Browser at Safest, personal device, not a work network. Come back every few days, not every hour. Each day you visit could be compared with who used Tor that day, so check less often and send several things at once.
sui-login-label = Your { $n }-word passphrase
sui-login-ten = Use { $n } separate boxes
sui-login-one = Use one box
sui-login-word = Word { $i }
sui-login-open = Open my mailbox
sui-login-wait = Opening your mailbox can take up to 30 seconds.
sui-login-err-count = Enter all { $n } words (you entered { $got }).
sui-login-err-word = Word { $i } is not in the word list. Check the spelling.
# @class critical
sui-login-err-auth = These words did not open a mailbox. Check each word and try again.
# @class critical
sui-login-failover = This site recently had an outage. If your passphrase worked before, your mailbox may be temporarily unavailable. Do not create a new mailbox unless the notice on { $info } tells you to. Try again in a few days.
# @class critical
sui-login-restored = You were signed out for safety. Your unsent message is kept for 20 minutes. Enter your passphrase to continue.
# @class critical
sui-login-files-lost = Files you were adding were not kept. Add them again after you sign in.
sui-login-lost = If you lost your passphrase
sui-inbox-step = Your report
sui-inbox-h1 = Your report
sui-inbox-status = Status: { $status }
sui-case-received = Received
sui-case-acknowledged = Acknowledged
sui-case-in-progress = In progress
sui-case-closed = Closed
# @class critical
sui-inbox-retention = Replies stay here for 30 days after they arrive. Copy down anything you need before then.
sui-inbox-messages = Messages
sui-inbox-none = No replies yet.
sui-msg-heading = Message from { $sender }, { $date } (UTC)
sui-inbox-actions = What you can do
sui-inbox-write = Write a message
sui-inbox-files = Add files
sui-inbox-rotate = Change my passphrase
sui-inbox-close = Close mailbox
sui-inbox-delete = Ask the team to delete my report
sui-inbox-logout = Log out
sui-inbox-offer = Change your passphrase now?
sui-inbox-offer-yes = Change it
sui-inbox-offer-no = Not now

## S11r Change passphrase

sui-rot-step = Change passphrase
sui-rot-h1 = Change your passphrase
# @class tier0
sui-rotate-explain = Changing your passphrase makes the old one stop working. Do it if someone may have seen your passphrase, or from time to time. On this website the server sees both passphrases while you change it, so this does not help if the server is compromised right now.
sui-rot-current = Your current passphrase
sui-rot-start = Make a new passphrase
# @class tier0
sui-rot-done-h1 = Your passphrase was changed
# @class tier0
sui-rot-done-text = Your old passphrase no longer works.
sui-back-inbox = Back to your mailbox

## S12 Secure Conversation

sui-conv-step = Messages
sui-conv-h1 = Messages
sui-conv-skip = Skip to reply form
# @class critical
sui-conv-gc36 = Only talk about your report here. The team should never ask you to move to email, phone or chat.
# @class critical
sui-conv-recipients = Your messages go only to people who could read your first report and are still on the team. People who joined later can read them only if the independent triage team gives them access.
sui-conv-reply = Write a message
sui-conv-text = Your message
sui-conv-file = Add a file (optional)
sui-conv-file-separate = Adding a file is a separate step: it does not send or save the message text above. Send your message first, or add the file before you write.
# @class tier0
sui-conv-send-anonymous = Send message
# @class tier0
sui-conv-send-confidential = Send message (confidential)
# @class tier0
sui-conv-send-identified = Send message (with my name)
# @class critical
sui-conv-sent = Your message was sent. The team receives new messages at fixed times each day, so it may take up to a day (or 1 to 3 more days if you chose a delay). Replies appear when you open your mailbox.
# @class critical
sui-conv-refused = The people who received your first report are no longer available. Send a new report or use { $route }.
sui-conv-identify = I want to tell the team who I am
sui-conv-delete = Delete the message from { $sender }, { $date } (UTC)
sui-conv-older = Older messages
sui-conv-newer = Newer messages
sui-conv-err-empty = Write a message or add a file.

## S13 Delete / Abandon / Close

sui-end-step = Discard
# @class tier0
sui-end-discard-h1 = Discard this report?
# @class tier0
sui-end-discard-text = Everything you entered and the files you added will be erased. Nothing has been sent.
sui-end-discard-yes = Discard
sui-end-discard-no = Keep working
# @class tier0
sui-end-discarded-h1 = Your report was discarded
# @class tier0
sui-end-discarded-text = Nothing was sent.
# @class critical
sui-new-identity = Now choose **New Identity** in the Tor Browser menu, then close Tor Browser.
sui-close-step = Close mailbox
# @class tier0
sui-close-h1 = Close your mailbox? Your passphrase will stop working
# @class tier0
sui-close-explain = Your passphrase will stop working. You won't be able to read replies or add information. Your report stays with the team. The team will learn that the mailbox was closed, only after a random delay of 3 to 21 days and only to the week. If you close it right after something happens at work, that timing could still point to you.
# @class tier0
sui-close-backups = Your login details are deleted from this server now; copies in server backups are deleted within { $days } days. If this server is ever restored from a backup, your deletion is applied again before it goes back online.
# @class tier0
sui-close-no-backups = Your login details are deleted from this server now. This server keeps no backups of them.
sui-close-passphrase = Type your passphrase to confirm
sui-close-yes = Close my mailbox
sui-close-no = Keep it open
# @class tier0
sui-closed-h1 = Your mailbox is closed
# @class tier0
sui-closed-text = Your passphrase no longer works. Your report stays with the team.
sui-askdel-step = Ask to delete
# @class tier0
sui-askdel-h1 = Ask the team to delete your report
# @class critical
sui-askdel-message = The team will get this message: "The source asks that this report be deleted."
# @class tier0
sui-askdel-honest = The team decides according to the law and their rules. They may need to keep some records.
sui-askdel-yes = Send this request
sui-askdel-no = Keep my report
sui-askdel-done-h1 = Your request was sent

## Leave, busy, error pages

sui-leave-step = Left
sui-leave-h1 = You have left
sui-leave-back = Back to start
sui-busy-step = Busy
sui-busy-h1 = This site can't take your request right now
sui-busy-text = Wait a minute, then choose Try again. Your text is kept for now.
# @class tier0
sui-busy-submit = Your report has not been sent yet. Your passphrase is still valid for this report.
sui-busy-retry = Try again
sui-notfound-step = Not found
sui-notfound-h1 = Page not found
sui-notfound-text = This page does not exist on this site.
sui-nav-start = Go to the start page
sui-error-step = Error
sui-error-h1 = Something went wrong
# @class critical
sui-error-text = Something went wrong. If the server restarted, your draft is lost and you need to start again. Nothing was sent unless you saw the page "Your report was sent".
sui-maint-step = Maintenance
sui-maint-h1 = This site is being updated
# @class critical
sui-maint-text = This site is being updated. Try again later. We never offer an anonymous version of this site anywhere else.
sui-signedout-step = Signed out
sui-signedout-h1 = You were signed out for safety
# @class critical
sui-signedout-text = For your safety, a session ends after 20 minutes without activity, and always after 2 hours. Anything you had not sent is lost. Nothing was sent unless you saw the page "Your report was sent".
sui-method-step = Not allowed
sui-method-h1 = This request is not allowed
sui-method-text = Go back to the start page and try again.

## Multi-part pages (AUD-RM1-SUI-01): long text is split into parts, never cut.

sui-part-status = This page is in { $total } parts so that it loads reliably. You are on part { $n }. Nothing is left out.
sui-part-continue-last = Check every part. The button to go on is on the last part.
sui-part-reply-last = The form to write a message is on the last part.
sui-part-nav = Parts of this page
sui-part-prev = Previous part
sui-part-next = Next part
sui-part-of = (part { $n } of { $total })
