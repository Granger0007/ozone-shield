/* Spot the Scam, Hard mode: messages built the way real scams work in the UK.
   Everything is invented. Brands are fictional; web addresses end in .example
   (reserved, so none of them can be a real site); phone numbers come from the
   ranges Ofcom keeps for drama, so none can ring a real person.

   Each message has:
     context  what you'd really know (your bank, what you're expecting)
     thread   earlier messages in the same conversation (not tappable)
     from     the full sender details, revealed when the player taps the sender
     parts    plain text, red flags {t, why}, and links {link, url, why?}:
              tapping a link shows where it really goes, like a long-press. */
window.OzoneGameHard = [
  /* ---------------- scams ---------------- */
  {
    id: 'h-thread-spoof', scam: true, cat: 'bank', channel: 'SMS', sender: 'Northgate',
    from: "Sender name: Northgate. It's a name, not a phone number.",
    context: 'You bank with Northgate Bank. The number on the back of your card is 03069 990100.',
    thread: [
      { who: 'them', text: 'Northgate: 482 910 is your code to log in. Never share it with anyone.', time: 'Mon 18:02' },
      { who: 'them', text: 'Northgate: You paid £12.40 to CITYTRANSIT. Not you? Call the number on your card.', time: 'Tue 08:15' }
    ],
    time: 'Today 21:14',
    parts: ['Northgate: ', { t: 'A new device was added to your online banking at 21:09.', why: 'A scary security event is the hook. It makes you act before you think.' },
      ' If this was NOT you, ', { t: 'call our fraud team now on 03069 990482', why: "Not the number on your card. A real alert sends you to the number you already have." },
      ' quoting ref NG-4471.'],
    lesson: "Sitting in your bank's real thread proves nothing: sender names can be faked. Call the number on your card, or 159."
  },
  {
    id: 'h-spoof-call', scam: true, cat: 'bank', channel: 'Call', sender: 'Northgate Bank',
    from: "Caller ID: Northgate Bank, 03069 990100.",
    context: 'You bank with Northgate Bank. The number on the back of your card is 03069 990100.',
    time: 'Incoming call · 2 min 40 s',
    parts: ['“Hello, this is James from the Northgate fraud team. ', { t: "We've stopped a payment of £1,280 to an online electronics shop.", why: 'A large payment you never made puts you in a panic.' },
      ' To cancel it, ', { t: "I'm sending you a one-time passcode. Please read it back to me.", why: "A bank will never ask you to read out a code. That code would approve the scammer's payment." },
      ' ', { t: "Please stay on the line, it'll only take a minute.", why: "Keeping you on the call stops you hanging up to check." }, '”'],
    lesson: "The number on screen matched the card, and it was still fake. If a caller asks for a code, it's fraud. Hang up and call 159."
  },
  {
    id: 'h-whatsapp-code', scam: true, cat: 'account', channel: 'WhatsApp', sender: 'Aunty Meera', known: true,
    from: "Saved contact: Aunty Meera, +44 7700 900612.",
    context: 'A text arrived a moment ago: "WhatsApp code 381-204. Don\'t share this code with others."',
    thread: [
      { who: 'them', text: 'Lovely to see you all on Sunday x', time: 'Sun 19:40' },
      { who: 'me', text: 'You too! Thanks for the food 😊', time: 'Sun 19:52' }
    ],
    time: 'Today 10:03',
    parts: ['Hi love, ', { t: "sorry, I've sent you a 6-digit code by mistake", why: "Nobody can send you a WhatsApp code by mistake. It was sent because someone is trying to log in as you." },
      ', ', { t: 'can you send it back to me?', why: "Sending the code hands over your WhatsApp account. The scammer then messages everyone in your contacts." },
      ' ', { t: 'Quick as I need it now x', why: 'Urgency, even from a familiar name.' }],
    lesson: 'Her account had been taken over, and this is how it spreads. Never share a WhatsApp code with anyone, even family. Call them on a number you know, and turn on two-step verification.'
  },
  {
    id: 'h-invoice', scam: true, cat: 'bank', channel: 'Email', sender: 'City Lettings Accounts',
    from: 'From: City Lettings Accounts <accounts@city-lettings-uk.example>. Reply-To: payments.citylettings@freemail.example',
    context: 'Your letting agent is City Lettings, at citylettings.example. Your rent of £1,150 is due on the 1st.',
    subject: 'Important: change of bank details for rent payments',
    time: 'Today 09:41',
    parts: ['Dear tenant, ', { t: 'following our annual audit, our bank account has changed.', why: 'Changed bank details by email is the classic payment-diversion trick. Real firms rarely change their account.' },
      ' From this month, please pay rent to the new account in the attached PDF. ', { t: "Please don't call the office about this, as we're moving to a new phone system.", why: "It stops you checking with the real agent, which is the one thing that would expose the scam." },
      ' ', { t: 'Payments to the old account will be returned and may incur a late fee.', why: 'A threat to rush you.' },
      ' Kind regards, Accounts Team'],
    lesson: "Look at the sender: city-lettings-uk.example isn't citylettings.example. Before paying new bank details, call the agent on a number you already have."
  },
  {
    id: 'h-road-charge', scam: true, cat: 'gov', channel: 'SMS', sender: '+44 7700 900318',
    from: "From the mobile number +44 7700 900318.",
    context: 'You drove through a toll road last month. You think you paid, but you are not certain.',
    time: 'Today 13:22',
    parts: ['GOV.UK: ', { t: 'You have an unpaid road charge of £2.95.', why: 'A small, believable amount. They want your card details, not the £2.95.' },
      ' ', { t: 'A penalty of £70 applies after today.', why: 'A same-day deadline with a big penalty.' }, ' Pay now: ',
      { link: 'gov.uk.road-charge-pay.example/pay', url: 'https://gov.uk.road-charge-pay.example/pay', why: 'The name just before the first single slash is road-charge-pay.example. Real government sites end .gov.uk, right before that slash.' }],
    lesson: "Read the address up to the first single slash. Here that's road-charge-pay.example; everything to its left, including gov.uk, is decoration."
  },
  {
    id: 'h-redelivery', scam: true, cat: 'parcel', channel: 'SMS', sender: 'Parcelwise',
    from: "Sender name: Parcelwise. It's a name, not a phone number.",
    context: "You're expecting a parcel from Parcelwise this week. Parcelwise's website is parcelwise.example.",
    time: 'Today 16:05',
    parts: ['Parcelwise: we missed you today. Choose a new delivery slot at ',
      { link: 'parcelwise.example-redelivery.example/slot', url: 'https://parcelwise.example-redelivery.example/slot', why: 'The site is example-redelivery.example, not parcelwise.example. The real name has been added to the front.' },
      '. ', { t: 'A £1.20 redelivery fee applies.', why: 'A tiny fee is the hook. What they really want is the card details you type in to pay it.' }],
    lesson: "You really were expecting a parcel, and that's what makes it work. Rebook through the courier's app or website, typed in yourself."
  },
  {
    id: 'h-tickets', scam: true, cat: 'prize', channel: 'WhatsApp', sender: '+44 7700 900764',
    from: 'Not in your contacts. Number +44 7700 900764.',
    context: "You asked on a fans' page if anyone had two tickets for Saturday's sold-out gig. This person replied.",
    time: 'Today 20:17',
    parts: ["Hey! I've got 2 standing tickets, can't go any more. ", { t: '£140 for both, face value.', why: 'Face value for a sold-out gig is what makes it feel genuine, and too good to miss.' },
      ' ', { t: 'Bank transfer only, PayPal takes fees', why: "Steering you away from payment methods with buyer protection. Money sent by bank transfer to a stranger is the hardest to get back." },
      '. ', { t: "I'll send them as soon as the money lands, lots of people asking so first to pay gets them.", why: 'You pay first, and pressure from other "buyers" stops you thinking.' }],
    lesson: 'Buy resale tickets through official resale sites, and pay by card. Never bank-transfer a stranger for tickets.'
  },
  {
    id: 'h-recovery', scam: true, cat: 'invest', channel: 'Email', sender: 'Funds Recovery Unit',
    from: 'From: Funds Recovery Unit <cases@funds-recovery-unit.example>',
    context: 'Two months ago you lost £3,000 to a fake investment app, and you reported it.',
    subject: 'Case 22841: your lost funds have been traced',
    time: 'Today 11:30',
    parts: ['Dear client, ', { t: 'we have traced the £3,000 you lost', why: 'Scammers sell lists of people who have already been scammed. Knowing your loss proves nothing.' },
      ' and can return it within 5 working days. ', { t: 'We work alongside Report Fraud and the police.', why: 'Name-dropping official bodies to borrow their trust. Report Fraud and the police never ask you to pay a fee to get money back.' },
      ' ', { t: 'A refundable release fee of £250 is required to start.', why: 'Paying to get your money back is the recovery scam: a second scam aimed at people who were already scammed.' }],
    lesson: 'Nobody genuine charges you up front to recover scam losses. Talk to your bank, and keep your Report Fraud reference.'
  },
  {
    id: 'h-voice-note', scam: true, cat: 'family', channel: 'WhatsApp', sender: '+44 7700 900255',
    from: 'Not in your contacts. Number +44 7700 900255.',
    context: "Your son Arjun is at university. His usual number is saved in your phone. The voice note sounds just like him.",
    time: 'Today 23:48 · Voice note 0:21 (transcript)',
    parts: ['🎙 “Mum, it\'s me. ', { t: "I've crashed the car and the other driver's really angry.", why: 'A sudden emergency, late at night, to stop you thinking clearly.' },
      ' ', { t: 'Can you send £900 to his account so he doesn\'t call the police?', why: 'Money straight to a stranger\'s account, to make a problem disappear.' },
      ' ', { t: "My phone's broken, this is a mate's. Don't ring Dad.", why: 'An excuse for the new number, and secrecy so nobody can check.' }, '”'],
    lesson: 'Voices can now be copied with AI from a short clip of audio, such as a video online. Call him on his usual number, and agree a family password for emergencies.'
  },
  {
    id: 'h-button-link', scam: true, cat: 'account', channel: 'Email', sender: 'Northgate Bank',
    from: 'From: Northgate Bank <alerts@northgate-bank.example>',
    context: 'You bank with Northgate Bank. Its website is northgate.example.',
    subject: 'Action needed: confirm a recent payment',
    time: 'Today 07:58',
    parts: ['We need you to confirm a payment of £640.00 made yesterday. ', { t: 'If we do not hear from you within 12 hours, your account will be restricted.', why: 'A deadline with a threat.' },
      ' ', { link: 'Review payment at northgate.example', url: 'https://northgate-secure-review.example/login', why: "The button says northgate.example, but it really goes to northgate-secure-review.example. The words on a button can say anything." },
      ' Thank you for banking with Northgate.'],
    lesson: 'Press and hold a link (or hover on a computer) to see where it really goes. Better still, open your banking app yourself.'
  },

  /* ---------------- genuine (and designed to make you doubt them) ---------------- */
  {
    id: 'h-real-alert', scam: false, cat: 'genuine', channel: 'SMS', sender: 'Northgate',
    from: "Sender name: Northgate. It's a name, not a phone number.",
    context: 'You bank with Northgate Bank. Earlier today you booked flights with SkyTravel for £249.',
    thread: [{ who: 'them', text: 'Northgate: 482 910 is your code to log in. Never share it with anyone.', time: 'Mon 18:02' }],
    time: 'Today 12:31',
    parts: ['Northgate: Did you try to pay £249.00 to SKYTRAVEL LTD? Reply Y if it was you, or N if not. We will never ask you to call a number in a text, share a code or move your money.'],
    lesson: "It's a payment you made, there's no link or number to call, and it asks for nothing but Y or N. If in doubt, you could still check in your banking app."
  },
  {
    id: 'h-real-delivery', scam: false, cat: 'genuine', channel: 'SMS', sender: 'Parcelwise',
    from: "Sender name: Parcelwise. It's a name, not a phone number.",
    context: "You ordered a lamp from Hartley Home. Their email said Parcelwise (parcelwise.example) will deliver it today.",
    time: 'Today 07:12',
    parts: ['Parcelwise: your parcel from Hartley Home arrives today, 13:00–14:00. Track it at ',
      { link: 'parcelwise.example/t/8KX2F', url: 'https://parcelwise.example/t/8KX2F' }, '.'],
    lesson: "You're expecting it, the link really goes to parcelwise.example, and it asks for no money or details."
  },
  {
    id: 'h-real-code', scam: false, cat: 'genuine', channel: 'SMS', sender: 'Northgate',
    from: "Sender name: Northgate. It's a name, not a phone number.",
    context: "You're logging in to Northgate online banking on your laptop right now, and it has asked for a code.",
    time: 'Now',
    parts: ["Northgate: 448 120 is your code to log in. It expires in 10 minutes. Never share it: Northgate staff will never ask you for it."],
    lesson: 'You asked for this code, so typing it into the bank\'s own website is fine. The danger is only when someone else asks you for it.'
  },
  {
    id: 'h-real-bill', scam: false, cat: 'genuine', channel: 'Email', sender: 'Brightline Energy',
    from: 'From: Brightline Energy <hello@brightline.example>',
    context: 'Your energy supplier is Brightline, at brightline.example. Prices went up across the market this winter.',
    subject: 'Your Direct Debit is changing',
    time: 'Yesterday 17:20',
    parts: ['Hi, from 1 March your monthly Direct Debit will change from £112 to £126, because of the new price cap. ',
      "You don't need to do anything. You can see the breakdown when you log in to your account at ",
      { link: 'brightline.example/account', url: 'https://brightline.example/account' }, '.'],
    lesson: "Unwelcome news isn't a scam sign. It comes from the supplier's own address, asks for nothing, and the link goes to brightline.example."
  },
  {
    id: 'h-real-flatmate', scam: false, cat: 'genuine', channel: 'WhatsApp', sender: 'Sam (flatmate)', known: true,
    from: "Saved contact: Sam (flatmate), +44 7700 900540. Two years of messages.",
    context: 'Sam is your flatmate. You split the bills every month, and the gas bill came this week.',
    thread: [
      { who: 'me', text: 'Gas bill came, did you see?', time: 'Wed 18:20' },
      { who: 'them', text: "Yep I'll pay it tonight", time: 'Wed 18:31' }
    ],
    time: 'Today 09:05',
    parts: ['Paid the gas, your half is £43.10. Send it whenever, no rush 👍'],
    lesson: "You expected it, it fits your conversation, and there's no pressure. Asking for money isn't a scam by itself: context is everything."
  },
  {
    id: 'h-real-call', scam: false, cat: 'genuine', channel: 'Call', sender: 'Northgate Bank',
    from: "Caller ID: Northgate Bank, 03069 990100.",
    context: 'You bank with Northgate Bank. The number on the back of your card is 03069 990100.',
    time: 'Incoming call · 1 min 10 s',
    parts: ["“Hello, it's Northgate Bank's fraud team. We've blocked a card payment that looked unusual. I won't ask for any codes, PINs or passwords. Please hang up and call the number on the back of your card, and we'll pick this up with you.”"],
    lesson: "Caller ID can be faked, so you can't trust the name on screen either way. This caller asks for nothing and tells you to call the number you already have: that's what a genuine fraud team does."
  }
];
