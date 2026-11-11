/* Spot the Scam: message library. Every message is made up for training.
   Strings are plain text; objects are tappable red flags with the reason. */
window.OzoneGameData = [
  {
    id: 'parcel-fee', scam: true, cat: 'parcel', channel: 'SMS', sender: 'Unknown number',
    parts: ['Royal Mail: ',
      { t: 'Your parcel is on hold due to an unpaid fee of £1.99.', why: "Small 'release fees' are a common trick to collect your card details." },
      ' ', { t: 'Pay within 24 hours', why: 'A short deadline is there to rush you before you think.' },
      ' or it will be returned to sender: ',
      { t: 'royalmail-redelivery-fee.com', why: "This isn't Royal Mail's website. Type the real address yourself instead of tapping a link." }],
    lesson: 'A fee demand, a deadline and a look-alike website: a classic delivery scam.'
  },
  {
    id: 'tax-refund', scam: true, cat: 'tax', channel: 'SMS', sender: 'HMRC-UK',
    parts: ['HMRC: ', { t: 'You are due a tax refund of £412.50.', why: 'HMRC never tells you about a tax refund by text, email or WhatsApp.' },
      ' ', { t: 'Claim within 48 hours', why: 'Deadline pressure again.' }, ' at ',
      { t: 'hmrc-refund-claim.uk', why: "HMRC's website is on gov.uk. This address isn't." }],
    lesson: "HMRC never contacts you about a tax refund by text or email, and its website is on gov.uk."
  },
  {
    id: 'safe-account', scam: true, cat: 'bank', channel: 'WhatsApp', sender: 'Bank Fraud Team',
    parts: ["This is your bank's fraud team. ", { t: 'Your account has been compromised.', why: 'Fear makes people act without checking.' },
      ' ', { t: 'Move your money to a safe account', why: "Banks never ask you to move money to a 'safe account'. This is always a scam." },
      " we've opened for you. ", { t: "Don't tell branch staff, they may be involved.", why: 'Asking for secrecy is a big warning sign. Your real bank wants you to talk to them.' }],
    lesson: "Hang up and call your bank on 159. 'Safe account' requests are always scams."
  },
  {
    id: 'hi-mum', scam: true, cat: 'family', channel: 'WhatsApp', sender: 'New number',
    parts: ['Hi Mum, ', { t: 'I dropped my phone, this is my new number.', why: "Scammers pretend to be family on a 'new number'." },
      ' ', { t: "Can you pay a bill for me? I'll pay you back tomorrow.", why: "An urgent money request from someone you can't verify." },
      ' ', { t: "Can't call, the mic is broken x", why: "An excuse not to talk, so you can't recognise their voice." }],
    lesson: 'Call your child on their old number before doing anything.'
  },
  {
    id: 'crypto-vip', scam: true, cat: 'invest', channel: 'WhatsApp', sender: 'Crypto Wealth VIP',
    parts: ['Welcome to our VIP trading group. ', { t: 'Guaranteed 30% returns every week.', why: 'No real investment can guarantee returns, let alone 30% a week.' },
      ' ', { t: 'Only 5 places left today.', why: 'False scarcity, to rush you.' }, ' Our mentor will help you ',
      { t: 'open an account on our trading app.', why: 'Scam groups use fake trading apps that show made-up profits.' }],
    lesson: 'Check the firm on the FCA Firm Checker before you send any money.'
  },
  {
    id: 'task-job', scam: true, cat: 'job', channel: 'WhatsApp', sender: 'Recruiter Sarah',
    parts: ["Hi! We're hiring remote staff. ", { t: 'Earn £300 a day just liking videos.', why: 'Pay that is far too good for a simple task.' },
      ' To get started, ', { t: 'pay a £50 registration fee.', why: "Real employers don't charge you to get a job." }],
    lesson: 'Any job that asks you to pay first is a scam.'
  },
  {
    id: 'account-locked', scam: true, cat: 'account', channel: 'Email', sender: 'Amazon Support <no-reply@amaz0n-support.net>',
    parts: ['Your account has been ', { t: 'suspended due to unusual activity.', why: 'A scary claim to make you act quickly.' },
      ' To restore access, ', { t: 'verify your card details', why: "Companies don't ask you to confirm card details through an email link." },
      ' at ', { t: 'amaz0n-secure-login.com', why: 'Look closely: a zero instead of the letter o.' }],
    lesson: 'Open the app or type the website yourself. Never log in through an email link.'
  },
  {
    id: 'vehicle-fine', scam: true, cat: 'gov', channel: 'SMS', sender: 'DVLA-INFO',
    parts: ['DVLA: ', { t: 'Your vehicle tax payment failed.', why: 'An unexpected payment problem is a common hook.' },
      ' ', { t: 'Update your card details now to avoid a £1,000 fine', why: 'Threats of a big fine create panic.' }, ': ',
      { t: 'dvla-vehicle-renew.co', why: "DVLA services are on gov.uk. This address isn't." }],
    lesson: 'Check your vehicle tax yourself on GOV.UK. Never pay through a text link.'
  },
  {
    id: 'energy-rebate', scam: true, cat: 'gov', channel: 'Email', sender: 'UK Energy Support <rebate@energy-support-uk.org>',
    parts: ['Good news! ', { t: "You're eligible for a £400 energy rebate.", why: 'Unexpected free money is bait.' },
      ' ', { t: 'Enter your bank details at the link below', why: "Don't give bank details through a link in an unexpected email." }, ' to receive it.'],
    lesson: 'An unexpected offer of free money that asks for your bank details is a scam.'
  },
  {
    id: 'prize', scam: true, cat: 'prize', channel: 'SMS', sender: 'PrizeDesk',
    parts: [{ t: "Congratulations! You've won an iPhone 17", why: "You can't win a draw you never entered." },
      ' in our customer draw. ', { t: 'Pay £2.50 delivery to claim', why: 'Paying to receive a prize is a trick to steal card details.' }, ' your prize today.'],
    lesson: 'If you have to pay to get a prize, there is no prize.'
  },
  {
    id: 'courier', scam: true, cat: 'bank', channel: 'SMS', sender: 'Police Alert',
    parts: ['Police: ', { t: 'Your bank card has been cloned.', why: 'Fear first, so you stop thinking.' },
      ' Cut it in half, then ', { t: 'a courier will collect it from your home.', why: 'Police and banks never send couriers to collect your card.' }],
    lesson: 'Never hand your card to anyone. Call your bank on 159.'
  },
  {
    id: 'romance', scam: true, cat: 'romance', channel: 'WhatsApp', sender: 'Daniel',
    parts: ["I've loved talking these past weeks. ", { t: "I'm stuck abroad and my bank card was blocked.", why: 'A sudden emergency far away is a classic romance scam turn.' },
      ' ', { t: 'Could you send £600 in gift cards?', why: 'Gift cards are hard to trace. Asking to be paid in gift cards is a classic scam sign.' },
      " I'll pay you back as soon as I'm home."],
    lesson: "Never send money to someone you haven't met in person."
  },
  {
    id: 'friend-coffee', scam: false, cat: 'genuine', channel: 'WhatsApp', sender: 'Priya',
    parts: ['Hey! Still on for coffee on Saturday at 11? Same place as last time.'],
    lesson: 'A contact you know, no links, no money, no pressure.'
  },
  {
    id: 'gp-reminder', scam: false, cat: 'genuine', channel: 'SMS', sender: 'ElmRoadGP',
    parts: ["Reminder: your appointment at Elm Road Surgery is on Thursday 14 January at 09:40. If you can't attend, please call the surgery."],
    lesson: 'No link, no payment, and it asks you to call the surgery on the number you already have.'
  },
  {
    id: 'bank-alert', scam: false, cat: 'genuine', channel: 'SMS', sender: 'YourBank',
    parts: ["We noticed a card payment of £89.99 at ElectroWorld. If this wasn't you, call the number on the back of your card. We will never ask for your PIN or passwords."],
    lesson: 'It asks for nothing and sends you to the number on your own card.'
  },
  {
    id: 'order-dispatched', scam: false, cat: 'genuine', channel: 'Email', sender: 'Hartley Books <orders@hartleybooks.co.uk>',
    parts: ['Thanks for your order! It has been dispatched and should arrive on Thursday. You can follow it in your account.'],
    lesson: 'Something you ordered, and no payment asked. Check it in your account, not through a link.'
  },
  {
    id: 'school-notice', scam: false, cat: 'genuine', channel: 'Email', sender: 'Oakfield Primary School',
    parts: ['Reminder: school closes at 1pm this Friday for staff training. After-school clubs are cancelled that afternoon.'],
    lesson: 'Information only: no links, money or personal details requested.'
  }
];
