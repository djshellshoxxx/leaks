# SPDX-License-Identifier: AGPL-3.0-or-later
# Source guidance cards (05-SOURCE-OPSEC.md §6), English master. All card text is sec:critical (05 §6).
# Key scheme: sops-<card>-title, -nN (normal paragraph), -liN (list item), -hN (higher-risk paragraph).

## Safety Check essentials (05 §7.1) and self-selection (05 §4.2)

# @class critical
sops-essential-1 = I am on a personal device, not a work device.
# @class critical
sops-essential-2 = I am not on a work or school network.
# @class critical
sops-essential-3 = I am using Tor Browser, set to Safest.
# @class critical
sops-essential-4 = No one can see my screen.
# @class critical
sops-essential-5 = I have not pasted anything into AI tools, translators or grammar checkers.
# @class critical
sops-essential-6 = I will describe or retype information rather than send files when I can.
# @class critical
sops-essential-7 = I have not printed documents to send.
# @class critical
sops-essential-8 = I am ready to keep a { $n }-word passphrase safe.
# @class critical
sops-selfselect-title = Are you at higher risk?
# @class critical
sops-track = Most people only need the **basic steps** above. Some people need more. If you are not sure, follow the higher-risk steps too. They take more time but give more protection.
# @class critical
sops-selfselect-intro = Open the "Higher risk" parts if **any** of these is true:
# @class critical
sops-selfselect-1 = Only a few people (about 10 or fewer) know what you are reporting.
# @class critical
sops-selfselect-2 = The report is about top managers, police, the military, intelligence, or powerful people.
# @class critical
sops-selfselect-3 = Your organization has tried to find out who reported things before.
# @class critical
sops-selfselect-4 = You could face arrest, violence, deportation, or a lawsuit if found.
# @class critical
sops-selfselect-5 = You live in a country that blocks or watches internet use.
# @class critical
sops-selfselect-6 = You have already been questioned, or you think you are being watched.
sops-high-summary = If you are at higher risk
sops-real-case = Real case:

## Groups

sops-group-a = A. Before you start
sops-group-b = B. Devices and browsers
sops-group-c = C. Networks and places
sops-group-d = D. Research and accounts
sops-group-e = E. Traces on your own devices
sops-group-f = F. What your organization may record
sops-group-g = G. What files reveal
sops-group-h = H. What your words reveal
sops-group-i = I. After you send your report
sops-group-j = J. More situations

## A. Before you start

# @class critical
sops-limits-title = What this site can and cannot do
# @class critical
sops-limits-n1 = **What this site does.** When you use Tor Browser, your internet address is hidden from us and from the people who read reports. We don't ask for your name. Our systems keep only the day your report is picked up for the team, not the time. The team sees { $profile ->
    [high] only the week
   *[other] only that day
}.
# @class critical
sops-limits-n2 = **What this site can't do.** It can't see or clean your computer or phone. It can't stop your employer or internet provider from seeing that you used Tor, and when. It can't remove every clue from your files or your words. The steps on this page help with those risks.
# @class tier0
sops-limits-n3 = **When you use this website:** your report is locked (encrypted) on our server as soon as it arrives. If the intake server is compromised or legally compelled while you use the website (no-JavaScript) version, what you type, and your passphrase when you log in, can be captured. For the highest risk, use the Candor Source App.
# @class critical
sops-limits-n4 = **Who reads reports:** Your report is first read by { $triage }. They may ask { $others } to help. You can tick people your report is about, and they will not get a key to open it.
# @class critical
sops-limits-oversight = { $label } can also read reports in this channel.
# @class critical
sops-limits-breakglass = In an emergency, { $roles }, including someone independent of management, can together give one more person access to a report for up to 8 hours. This is recorded and reviewed.
# @class critical
sops-limits-escrow-none = There is no backup key.
# @class critical
sops-limits-escrow = A backup key is split between { $holders }. { $k } of them together could unlock reports.
# @class critical
sops-limits-reduced-sod = This organization has few staff for this service, so fewer people check each other than usual. { $label } oversees it.
# @class critical
sops-legal-title = Your rights and your safety
# @class critical
sops-legal-n1 = This site does not give legal advice. Laws about reporting are different in each country and job. A lawyer, a union, or a whistleblower support group can explain your rights.
# @class critical
sops-legal-n2 = If you are in danger right now, contact your local emergency services.

## B. Devices and browsers

# @class critical
sops-device-title = Use the right device
# @class critical
sops-device-n1 = **Use a personal computer that your employer has never managed.** Don't use a work laptop, work phone, or a shared computer that other people can look at. A computer you own and control is best.
# @class critical
sops-device-h1 = Use a computer that has never been used for work, or start it with **Tails** (see "Tails"). Avoid phones if you can. Phones keep detailed records and your location history. If you must use a phone, use Tor Browser for Android.
# @class critical
sops-managed-title = Work devices are watched
# @class critical
sops-managed-n1 = Work computers and phones often have security software you can't see. It can record the websites you visit, the files you open or copy, and sometimes your screen. **Using Tor on a work device can itself set off an alert.**
# @class critical
sops-managed-n2 = Don't use a work device for anything about this report: not to search, not to write notes, not to copy files. This also applies to a personal phone that has a work profile or a "company portal" app.
# @class critical
sops-managed-h1 = Don't try to turn off or get around monitoring software. Trying is often recorded and can draw attention to you. Don't connect your personal phone to a work computer, even to charge it.
# @class critical
sops-browser-title = Use Tor Browser
# @class critical
sops-browser-n1 = Use **Tor Browser**. Get it only from the Tor Project's official site: torproject.org.
# @class critical
sops-browser-n2 = Other tools don't protect you the same way:
# @class critical
sops-browser-li1 = **Private or incognito windows** only stop your own browser from keeping history. Your network and websites still see you.
# @class critical
sops-browser-li2 = **A VPN** hides your activity from your local network, but the VPN company can see it and may keep records.
# @class critical
sops-browser-li3 = **Other browsers with a "Tor window"** are not the same as Tor Browser.
# @class critical
sops-browser-li4 = **On iPhone or iPad**, the only choice is Onion Browser, which gives weaker protection. Use a computer or an Android phone if you can.
# @class critical
sops-browser-h1 = Check the download's signature, following the steps on torproject.org. Keep Tor Browser up to date. Don't add extensions or change advanced settings. That makes your browser stand out.
# @class critical
sops-safest-title = Set Tor Browser to "Safest"
# @class critical
sops-safest-n1 = Click the **shield** icon, then **Settings**, and choose **Safest**. This turns off JavaScript, which blocks many attacks. This site works fully at Safest.
# @class critical
sops-safest-n2 = If you see a yellow box saying "JavaScript is on", change the setting and reload the page.
# @class critical
sops-safest-h1 = Check the setting before each visit. When you finish, choose **New Identity** from the Tor Browser menu, then close Tor Browser.
# @class critical
sops-tails-title = Tails: a safer system for high-risk reporting
# @class critical
sops-tails-n1 = If you are at higher risk, consider Tails. See below.
# @class critical
sops-tails-h1 = **Tails** is a free system you start from a USB stick. It sends all internet traffic through Tor and forgets everything when you shut down, so it leaves almost no traces on the computer. Get it from tails.net on a device you trust, and follow its install and check steps. If you can, use a new USB stick you bought with cash. Tails includes a screen reader (Orca) and a screen magnifier.
# @class critical
sops-tier-title = Website or app?
# @class critical
sops-tier-n1 = You can use this **website** in Tor Browser, or the **Candor app**.
# @class tier0
sops-tier-li1 = **The website** needs nothing installed. But our server encrypts your report after it arrives. If the intake server is compromised or legally compelled while you use the website (no-JavaScript) version, what you type, and your passphrase when you log in, can be captured.
# @class critical
sops-tier-li2 = **The app** encrypts your report on your own device before sending, checks that it is talking to the right team, checks for replies without telling the server which mailbox is yours, and can clean hidden data from photos and documents. It keeps everything it remembers — which organization, its address, and its safety checks — locked inside one encrypted file that your passphrase opens; that file looks the same whether or not you ever sent a report. But the installed app itself is a sign that you may have used it if someone searches your device.
# @class critical
sops-tier-n2 = **Getting the app.** Download it in Tor Browser from the Candor project's address: { $address }. { $org } does not offer the app on its own website. App stores (such as Google Play or the Apple App Store) keep a record that your account downloaded it. On iPhone and iPad the app is only in the App Store. **Never install it on a phone or computer your employer manages**, including a phone with a work profile.
# @class critical
sops-tier-h1 = Use the app, ideally the desktop app on Tails, downloaded over Tor. Tor's connection encryption does not yet resist future quantum computers, so someone who records internet traffic today might later read what was typed into the website. The app adds encryption designed to resist this. If your device could be searched and you can't use Tails, use the website in Tor Browser and accept the risk above.

## C. Networks and places

# @class critical
sops-torvisible-title = Your network can see that you use Tor
# @class critical
sops-torvisible-n1 = The people who run your network can see **that** you use Tor, but not **which** sites you visit. At home, that is your internet provider. At work or school, it is your employer, and very few people there may use Tor.
# @class critical
sops-torvisible-n2 = Real case: a student who used Tor on his university's Wi-Fi was found because he was one of very few Tor users on that network at that time.
# @class critical
sops-torvisible-n3 = **Never use a work or school network**, including work Wi-Fi, office guest Wi-Fi, or a work VPN.
# @class critical
sops-torvisible-h1 = Use a network that isn't linked to you, or use a bridge (see "Bridges"). Don't use the same network every time.
# @class critical
sops-bridges-title = Bridges hide that you use Tor
# @class critical
sops-bridges-n1 = A **bridge** is a less visible way into the Tor network. It makes it harder for your network to tell that you use Tor. In Tor Browser, go to **Settings → Connection → Bridges** and choose a built-in bridge. **WebTunnel** looks like ordinary web browsing. **obfs4** and **Snowflake** are other choices. A bridge does **not** make a work device safe.
# @class critical
sops-bridges-h1 = Built-in bridges are publicly listed and can be recognized. Use **Request a bridge** in Tor Browser to get a less-known one. Don't request bridges from an email or chat account linked to you.
# @class critical
sops-censorship-title = If Tor is blocked
# @class critical
sops-censorship-n1 = If Tor Browser can't connect, your country or network may be blocking Tor. Use Tor Browser's **Connection Assist**. It suggests a bridge that works where you are.
# @class critical
sops-censorship-n2 = If this site is down, **don't use another "anonymous" address you find elsewhere.** We never offer an anonymous version of this site outside Tor. Check the address again later at { $info }.
# @class critical
sops-censorship-h1 = Where using Tor is dangerous, think about your personal safety before you try. A digital-safety group you trust can help.
# @class critical
sops-place-title = Where you are
# @class critical
sops-place-n1 = Choose a private place where no one can see your screen. Watch for cameras, windows and mirrors behind you. Don't do this at work, in a work car, or near work colleagues.
# @class critical
sops-place-h1 = **Your phone records where you go.** If you travel somewhere to send your report, leave your phone at home. Go at a time that fits your usual routine. Pay with cash. Avoid seats in view of cameras, and don't go back to the same place each time.

## D. Research and accounts

# @class critical
sops-research-title = Look things up safely
# @class critical
sops-research-n1 = You may want to look up how to report, what the law says, or this site's address. **Do that in Tor Browser too, on your personal device.** Searches on work devices, or while logged in to Google, Microsoft, Apple or similar accounts, are saved and can be seen later.
# @class critical
sops-research-h1 = In the days before you report, don't look at pages about the issue in a way that stands out, especially at work. That includes internal pages, news stories and company pages.
# @class critical
sops-accounts-title = Don't log in to anything
# @class critical
sops-accounts-n1 = Don't log in to email, social media, work accounts, or any account with your name while you use Tor Browser for this report. Never use work email, work chat or a work calendar for anything about your report.
# @class critical
sops-accounts-h1 = Don't create new accounts (like a new email address) for your report unless you really need one. Every account is another trail.
# @class critical
sops-cloud-title = Keep files out of the cloud
# @class critical
sops-cloud-n1 = Files in OneDrive, Google Drive, iCloud, Dropbox or SharePoint are copied to company servers, often with a record of who opened, downloaded or shared them. **Don't save report files or notes in any cloud folder.** Check that your personal device doesn't copy your Desktop or Documents folders to the cloud. Don't email files to yourself.
# @class critical
sops-cloud-n2 = Only use information you had a lawful reason to access. Ask a lawyer if you are not sure.
# @class critical
sops-cloud-h1 = Assume your organization's systems record who opened, downloaded, copied, printed or emailed each document, and when. That list can be very short. In your report, say roughly how many people could have had the same information. This helps the team protect you.
# @class critical
sops-ai-title = Never paste into AI tools, translators or grammar checkers
# @class critical
sops-ai-n1 = **Never paste your report, notes or documents into:**
# @class critical
sops-ai-li1 = AI chatbots or writing assistants (for example ChatGPT, Copilot, Gemini or Claude),
# @class critical
sops-ai-li2 = online translators (for example Google Translate or DeepL),
# @class critical
sops-ai-li3 = grammar or spelling services (for example Grammarly),
# @class critical
sops-ai-li4 = AI features built into office apps, email, browsers or phone keyboards.
# @class critical
sops-ai-n2 = These services send your text to a company that may keep it. **Your employer may be able to see what you typed into work versions of these tools.**
# @class critical
sops-ai-h1 = Turn off cloud-based keyboard features on your phone, such as online prediction and voice typing.

## E. Traces on your own devices

# @class critical
sops-history-title = History and downloads
# @class critical
sops-history-n1 = Tor Browser forgets your browsing when you close it. Other browsers don't. If you used another browser to find this site or read about reporting, clear that browser's history. This site never asks you to download anything.
# @class critical
sops-history-h1 = Deleted files can often be brought back with special tools, especially from USB sticks and older hard drives. Tails avoids creating these files in the first place.
# @class critical
sops-traces-title = Recent files, previews and system records
# @class critical
sops-traces-n1 = Your computer keeps lists of recently opened files and small preview pictures (thumbnails). Word, PDF readers, the Windows "Recent" list and the Mac "Recents" folder can show which files you opened for your report.
# @class critical
sops-traces-h1 = Computers also keep system records: which USB drives were connected and when, which programs ran, search indexes of file contents, and backups (like Windows File History or Mac Time Machine). An expert can read these. You cannot reliably remove them all on a normal computer. Tails is designed to avoid them.

## F. What your organization may record

# @class critical
sops-monitoring-title = Security monitoring at work
# @class critical
sops-monitoring-n1 = Many organizations use security tools (sometimes called **EDR** or **DLP**) on work computers, email and networks. These tools can record files you open, copy, upload, print or email, the websites you visit, USB drives you plug in, and sometimes screenshots or keystrokes. They can alert security staff when someone copies sensitive files. **Assume anything you did on work systems can be looked at later.**
# @class critical
sops-monitoring-h1 = These records are often kept for months. If you copied or printed documents in the past, that may already be recorded. Think about this before you decide what to send.
# @class critical
sops-print-title = Don't print
# @class critical
sops-print-n1 = **Don't print documents to send them.** Work printers and copiers keep records of who printed what and when.
# @class critical
sops-print-n2 = Real case: a leaked document was traced partly because the organization's records showed only six people had printed it.
# @class critical
sops-print-h1 = Don't use work scanners or copiers either. They keep records and sometimes copies.
# @class critical
sops-usb-title = USB drives and memory cards
# @class critical
sops-usb-n1 = Work computers often record every USB drive that is plugged in, including its serial number. Don't plug personal drives into work computers, and don't plug work drives into your personal device.
# @class critical
sops-usb-h1 = USB sticks and memory cards keep deleted files and hidden records. Real case: police found a deleted file with a church name and a first name on a floppy disk the sender believed could not be traced. If you must move files, use a new drive that has never touched a work device, and don't send the drive itself to anyone.

## G. What files reveal

# @class critical
sops-exif-title = Hidden data in photos
# @class critical
sops-exif-n1 = Photos from phones and cameras usually hold hidden information: the **exact location**, the date and time, and the phone model. Real case: a published photo's hidden location data showed where a man in hiding was.
# @class critical
sops-exif-n2 = Turn off location for your camera before taking photos. When possible, **describe or retype** what a picture shows instead of sending it.
# @class critical
sops-exif-n3 = On this website, we can't remove hidden data before your file is locked. The team normally views a cleaned copy, but your original file is kept as evidence.
# @class critical
sops-exif-h1 = Even with hidden data removed, experts can sometimes match a photo to the camera that took it, because each camera sensor leaves a tiny unique pattern. Don't send photos from a phone whose other photos are online or on work systems.
# @class critical
sops-docmeta-title = Hidden data in documents
# @class critical
sops-docmeta-n1 = Word, Excel, PowerPoint and PDF files carry hidden details: **author names, company name, "last edited by", your computer's user name, folder names like C:\Users\jsmith, comments, tracked changes, and older versions of the text.** Opening and saving a file on your own computer can add your name.
# @class critical
sops-docmeta-n2 = The safest way to share what a document says is to **copy the important parts into the form as plain text.**
# @class critical
sops-docmeta-h1 = Some hidden details can link a file to the exact computer that edited it. PDFs can hold older versions inside them. The "remove personal information" features in office software don't remove everything. The team normally reads a cleaned copy, but the original is kept as evidence and may still hold these details.
# @class critical
sops-filenames-title = File names and file dates
# @class critical
sops-filenames-n1 = File names can give you away, like "JSmith_notes.docx" or "Copy of budget (2).xlsx". **This site replaces your file names with plain ones like "file-01.pdf" unless you choose to keep them.**
# @class critical
sops-filenames-h1 = Files also carry dates for when they were created and changed. Zip files store names, dates and sometimes user names for every file inside, and zip files made on a Mac may include hidden extra files. Don't send zip files unless you need to.
# @class critical
sops-canary-title = Unique copies ("canary traps")
# @class critical
sops-canary-n1 = Some organizations give different people slightly different versions of a document, with different words, spacing or numbers. If you send your copy, those small differences can show it was yours. **If only a few people had a document, describe what it says instead of sending it**, or retype a short part in plain words.
# @class critical
sops-canary-h1 = Retyping removes some hidden marks, but not differences in wording or numbers. Don't go looking for extra copies you don't normally use. That access may be recorded.
# @class critical
sops-watermark-title = Invisible watermarks
# @class critical
sops-watermark-n1 = Documents, images and even your work screen can carry **invisible marks** that show who received or viewed them. Some are hidden characters in text. Some are tiny changes in pictures. Some screen tools add your user ID to everything shown on your work screen. You can't see or check for these marks yourself.
# @class critical
sops-watermark-h1 = Retyping text by hand removes hidden characters, but not unique wording. A photo of a work screen can capture an invisible screen watermark.
# @class critical
sops-dots-title = Printer tracking dots
# @class critical
sops-dots-n1 = Many color laser printers add tiny yellow dots to every page. The dots can show the printer's serial number and the print time. Photos and scans of printed pages carry the dots too. If you send a picture of a printed page, **tell the team it was printed** so they can handle it carefully.
# @class critical
sops-screenshots-title = Screenshots
# @class critical
sops-screenshots-n1 = Screenshots can show much more than you expect: your user name, email, open tabs, messages that pop up, the time, and your desktop picture. On work computers, taking a screenshot can be recorded. **Crop tightly** to the part that matters, or better, **retype** it.
# @class critical
sops-screenshots-h1 = Screenshot files hold hidden data such as the device name and time. A screen's layout can be matched to one computer or one account.
# @class critical
sops-background-title = Photos of documents and what's in the background
# @class critical
sops-background-n1 = Before you take a photo, check what else is in it: your desk, hands, rings, tattoos, a view from a window, reflections in the screen or in glasses, an ID badge, or a sticker on a monitor. Use a plain background and photograph only what you need.
# @class critical
sops-background-h1 = The room, angle, lighting and even the type of paper can point to a place. Photos of a work screen may show your login name or an invisible watermark.

## H. What your words reveal

# @class critical
sops-content-title = Details that point to you
# @class critical
sops-content-n1 = Details can point to you even without your name. For example: "I was in the meeting on 4 May", "as the only night-shift nurse", your job title, or something only you were told.
# @class critical
sops-content-n2 = The team needs facts to act, so you don't have to leave everything out. Instead:
# @class critical
sops-content-li1 = Say **what happened** and **where evidence can be found**.
# @class critical
sops-content-li2 = Use "early May" instead of an exact date if the exact date would point to you.
# @class critical
sops-content-li3 = Say which details **only a few people know**. The team can then be careful when they investigate.
# @class critical
sops-content-h1 = For each detail, think about who could have known it. If fewer than about five people know it, ask yourself whether the team needs it now. The team can ask questions later through your secure mailbox, and you decide what to share.
# @class critical
sops-style-title = Your writing style
# @class critical
sops-style-n1 = Your writing style, meaning your favorite words, spelling, punctuation, greetings and emojis, can be matched to emails you wrote at work. Your employer has a lot of your writing. **Keep messages short and factual.** Use simple sentences or lists. Leave out greetings, sign-offs, jokes and your usual phrases. Don't use online AI tools to rewrite your text.
# @class critical
sops-style-h1 = Computers can now match writing styles well, especially when only a few people could be the writer. Write as plainly as you can. If someone you trust helps you reword your report, remember that they then know about it.

## I. After you send your report

# @class tier0
sops-passphrase-title = Keep your passphrase safe
# @class tier0
sops-passphrase-n1 = Before your report is sent, you get a **passphrase of { $n } words**, and you type 3 of them to show you kept it. It is the only way to read replies and add information. **No one can reset it or send it to you again**, not us and not the team.
# @class tier0
sops-passphrase-li1 = Write it on paper and keep it somewhere private, away from work things. Or save it in a password manager on a personal device that doesn't sync to a work account.
# @class tier0
sops-passphrase-li2 = Don't keep it in email, notes apps, photos, chats or cloud documents.
# @class tier0
sops-passphrase-li3 = Don't share it. Anyone who has it can read replies and write as you.
# @class tier0
sops-passphrase-li4 = You can change it later in your mailbox ("Change my passphrase").
# @class tier0
sops-passphrase-h1 = Try to learn it by heart. Practice it over the next few days, then destroy the paper. If you use Tails, you can keep it in Tails' encrypted Persistent Storage. Change your passphrase now and then, and whenever you think someone may have seen it.
# @class critical
sops-return-title = Checking for replies
# @class critical
sops-return-n1 = Replies can take days or weeks. The team aims to confirm they received your report within { $days } days. **Come back after a few days, not every hour.** Follow the same steps each time: personal device, Tor Browser, not a work network. Replies show the date only.
# @class critical
sops-return-n2 = **Each day you visit can be compared with a list of who used Tor that day.** Over several visits, comparing those lists can narrow them down to you. Visit only when you need to, and put everything you want to say into one message instead of several visits.
# @class critical
sops-return-h1 = Visit rarely, at times that fit your usual routine, and from different networks when you can. Don't visit right after an event others know about, such as the day after a meeting where the issue came up. A reply may be sent to prompt you to come back; you don't have to come back quickly. On the website, a compromised server could note each time you sign in. The Candor app checks for replies without telling the server which mailbox is yours.
# @class critical
sops-timing-title = Timing
# @class critical
sops-timing-n1 = **When** you do things can point to you. Don't send your report from work or during your work hours. Avoid sending it right after you opened or copied documents at work.
# @class critical
sops-timing-n2 = When you send, you can choose **"deliver after a random delay of 1 to 3 days"**. Then the day the team receives your report is less likely to match what you did at work.
# @class critical
sops-timing-h1 = If someone knows roughly when a report arrived, they may compare that with who was off work, who used Tor, or who opened files. **Our systems keep only the day your report is picked up, not the time, and the team sees only { $profile ->
    [high] the week
   *[other] the day
}.** But your own network, your device, and anyone watching this site's network can record the exact time. Choose the delay. Consider also waiting some days after gathering information before you send.
# @class critical
sops-seizure-title = If your device is taken or searched
# @class critical
sops-seizure-n1 = If your device is taken or searched, or you are asked to hand it over:
# @class critical
sops-seizure-li1 = Get legal advice before you answer questions, if you can.
# @class critical
sops-seizure-li2 = **Don't destroy or hide anything that may be evidence.** That can be a crime.
# @class critical
sops-seizure-li3 = This site does not store your name. What can be found depends on your device: files you saved, your passphrase if you wrote it down, browser traces, and the Candor app if you installed it.
# @class critical
sops-seizure-li4 = If someone may have seen your passphrase, they can read replies. When it is safe and legal to do so, you can **change your passphrase** so the old one stops working, **close your mailbox**, or send a message telling the team the passphrase may be known. Closing your mailbox does not delete your report.
# @class critical
sops-seizure-li5 = The team will learn that the mailbox was closed. If you close it right after something happens at work, such as interviews, that timing could point to you.
# @class critical
sops-seizure-h1 = Plan ahead. If your device could be searched, use Tails and don't keep files or notes. In some places you can more easily be forced to unlock a phone with your face or fingerprint than with a passcode.
# @class critical
sops-sidechannel-title = Keep the conversation here
# @class critical
sops-sidechannel-n1 = Only talk about your report through this secure mailbox. The team should never ask you to move to email, phone, chat or social media. If a message asks you to, be careful. Don't tell friends or colleagues about your report.
# @class critical
sops-sidechannel-n2 = Real case: someone shared secrets in an online chat with a person they trusted, and that person reported them to the authorities.
# @class critical
sops-retaliation-title = If you are treated unfairly
# @class critical
sops-retaliation-n1 = If you think you are being treated badly because someone suspects you reported, you can tell the team through your mailbox. Keep a private record of what happens, not on a work device.

## J. More situations

# @class critical
sops-lostphrase-title = If you lose your passphrase
# @class critical
sops-lostphrase-n1 = No one can reset or resend your passphrase. If you lose it, you can send a new report. If you want the team to connect it with your earlier report, mention something only the first report contained. This links the two reports, so do it only if you are comfortable with that. Don't contact the team by email or phone to explain.
# @class critical
sops-selfhint-title = Who you report about can point to you
# @class critical
sops-selfhint-n1 = Ticking people your report is about keeps them from getting a key. But your ticks are seen by the independent team that reads reports first, and they can say something about you. If you tick your own manager, that team can tell which team you work in. Tick what you need to keep the right people out, and no more.
# @class critical
sops-phoneonly-title = If you only have a phone
# @class critical
sops-phoneonly-n1 = If a phone is your only device, use Tor Browser for Android on a phone your employer has never managed and that has no work profile. On iPhone, only Onion Browser is available, and it protects you less. Phones keep location history and often back up photos and notes to the cloud; turn that off for anything about your report. Don't use keyboard apps with online prediction or voice typing. If you can borrow or buy a cheap computer and use Tails, that is safer.
# @class critical
sops-phoneonly-h1 = Leave the phone you normally carry at home when you report, and never use a phone that your employer pays for or manages.
# @class critical
sops-warnings-title = Warnings on this site
# @class critical
sops-warnings-n1 = The people who run this service publish a signed statement every month saying the service has not been secretly changed or ordered to watch users. If this site shows a warning that the statement is missing or out of date, or shows an incident notice, stop and think before you continue. A missing statement can be harmless, and people can be forced to publish false statements, so it is a signal, not a guarantee. On the website, the warning is shown by the same server it is about, so a server under someone else's control could hide it. The Candor app checks the statement by itself.
# @class critical
sops-firstcontact-title = Finding this site safely
# @class critical
sops-firstcontact-n1 = Find this site's address without using a work device or work network. If you saw the address on a poster, card or intranet page, write it down and type it into Tor Browser later, at home. Don't click a "speak up" or "report a concern" link on a work computer: visiting that page from work can be recorded, and that record can be compared with when a report arrives.
# @class critical
sops-appvault-title = What the app keeps on your device
# @class critical
sops-appvault-n1 = The Candor app creates one locked file as soon as it is installed, before you use it. Everything the app remembers — the organization's address, its safety checks and your mailbox list — is kept only inside that file, and only your passphrase opens it. The file has the same size whether or not you ever sent anything, and a wrong passphrase looks the same as an empty app. This does **not** hide that the app is installed. If you remove the app's data, the app replaces the file with an empty one of the same size.
# @class critical
sops-appvault-h1 = Phones and USB sticks can keep old copies of files. If your device could be searched, use the desktop app on Tails, where nothing stays after you shut down.
# @class critical
sops-identified-title = If you choose to give your name
# @class critical
sops-identified-n1 = You can choose to tell the team who you are, also through this site. Your name and contact details are then locked away separately and are opened only by the named identity custodians under strict rules; the case team works with the report without seeing them unless you agree or the law requires it. The banner at the top of the page changes to show that you have identified yourself. Using Tor Browser still hides your internet connection, but it no longer makes you anonymous to the organization.
