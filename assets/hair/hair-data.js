/* Hair Day — data: palettes, translations, hairstyle catalog, special days */
(function (global) {
  "use strict";

  /* ---------------------------------------------------------------- colors */
  const HAIR_COLORS = {
    black: { hex: "#2b2028", shade: "#180f18", light: "#4a3946", en: "Black", pt: "Preto" },
    darkbrown: { hex: "#42291d", shade: "#2a1810", light: "#654134", en: "Dark brown", pt: "Castanho escuro" },
    chestnut: { hex: "#6b4126", shade: "#4a2b17", light: "#8f5c39", en: "Chestnut", pt: "Castanho" },
    caramel: { hex: "#9c6434", shade: "#75471f", light: "#c08a55", en: "Caramel", pt: "Caramelo" },
    blonde: { hex: "#d9a355", shade: "#b57f37", light: "#f0cd8c", en: "Blonde", pt: "Loiro" },
    ginger: { hex: "#b5551f", shade: "#8b3c12", light: "#dd7c3f", en: "Ginger", pt: "Ruivo" },
    pink: { hex: "#f0629e", shade: "#c93f78", light: "#ff9cc4", en: "Pink", pt: "Rosa" },
    lilac: { hex: "#a877e0", shade: "#8154bb", light: "#c9a4f2", en: "Lilac", pt: "Lilás" },
    blue: { hex: "#4f8ee0", shade: "#3466b5", light: "#84b4f0", en: "Blue", pt: "Azul" },
    mint: { hex: "#48c9b0", shade: "#2d9e88", light: "#84e2d0", en: "Mint", pt: "Verde menta" },
    silver: { hex: "#b9b3c4", shade: "#8e8899", light: "#ddd9e4", en: "Silver", pt: "Prateado" },
    rainbow: { hex: "#ff6fae", shade: "#c94f90", light: "#ffd166", rainbow: true, en: "Rainbow", pt: "Arco-íris" }
  };

  const SKIN_TONES = {
    porcelain: "#f7d9c6",
    light: "#efc3a4",
    golden: "#e0a879",
    tan: "#c98b5f",
    bronze: "#a86a41",
    brown: "#7d4a2c",
    deep: "#57301c"
  };

  const ACC_COLORS = {
    pink: "#ff6fae", red: "#e63946", gold: "#ffc83d", white: "#ffffff",
    purple: "#8b5cf6", green: "#3faa61", blue: "#3b8ede", orange: "#ff8a3d",
    black: "#2b2028", mint: "#2dd4bf"
  };

  /* ------------------------------------------------------------- interface */
  const UI = {
    appName: { en: "Hair Day", pt: "Dia do Cabelo" },
    tagline: {
      en: "A hairstyle for every single day of the year.",
      pt: "Um penteado para cada dia do ano."
    },
    menuToday: { en: "Today's Hairstyle", pt: "Penteado de Hoje" },
    menuTodayD: { en: "See what your hair wants to be today.", pt: "Veja o que seu cabelo quer ser hoje." },
    menuYear: { en: "The Whole Year", pt: "O Ano Inteiro" },
    menuYearD: { en: "All 365 days, holidays and seasons included.", pt: "Os 365 dias, com feriados e estações." },
    menuHow: { en: "How To Do It", pt: "Como Fazer" },
    menuHowD: { en: "Step-by-step instructions for every style.", pt: "Passo a passo de todos os penteados." },
    menuSalon: { en: "Hair Salon", pt: "Salão de Beleza" },
    menuSalonD: { en: "Invent your own hairstyle and save it.", pt: "Invente seu penteado e salve." },
    menuGame: { en: "Copy Cat Challenge", pt: "Desafio Copia-Gato" },
    menuGameD: { en: "Copy the client's hairstyle before time runs out!", pt: "Copie o penteado da cliente antes do tempo acabar!" },
    menuMemory: { en: "Memory Game", pt: "Jogo da Memória" },
    menuMemoryD: { en: "Find the matching pairs of hairstyles.", pt: "Ache os pares de penteados." },
    menuBook: { en: "My Lookbook", pt: "Meu Álbum" },
    menuBookD: { en: "Your saved styles and your favourites.", pt: "Seus penteados salvos e favoritos." },
    menuSettings: { en: "Settings", pt: "Ajustes" },
    menuSettingsD: { en: "Your hair, your birthday, your special days.", pt: "Seu cabelo, aniversário e dias especiais." },

    back: { en: "Back", pt: "Voltar" },
    today: { en: "Today", pt: "Hoje" },
    tomorrow: { en: "Tomorrow", pt: "Amanhã" },
    yesterday: { en: "Yesterday", pt: "Ontem" },
    howToDoThis: { en: "How do I do this?", pt: "Como eu faço?" },
    surprise: { en: "Surprise me!", pt: "Me surpreenda!" },
    favourite: { en: "Favourite", pt: "Favoritar" },
    favourited: { en: "Favourited", pt: "Favoritado" },
    minutes: { en: "min", pt: "min" },
    easy: { en: "Easy", pt: "Fácil" },
    medium: { en: "Medium", pt: "Médio" },
    tricky: { en: "Tricky", pt: "Difícil" },
    youNeed: { en: "You will need", pt: "Você vai precisar" },
    steps: { en: "Steps", pt: "Passo a passo" },
    tipTitle: { en: "Tip", pt: "Dica" },
    pickStyle: { en: "Pick a hairstyle", pt: "Escolha um penteado" },
    search: { en: "Search…", pt: "Buscar…" },
    thisWeek: { en: "This week", pt: "Esta semana" },
    nothingHere: { en: "Nothing here yet.", pt: "Nada aqui ainda." },

    yearOf: { en: "Hair year", pt: "Ano do cabelo" },
    prevYear: { en: "Previous year", pt: "Ano anterior" },
    nextYear: { en: "Next year", pt: "Próximo ano" },
    legendSpecial: { en: "Special day", pt: "Dia especial" },
    legendToday: { en: "Today", pt: "Hoje" },

    salonHint: {
      en: "Mix and match until it looks amazing, then save it to your lookbook.",
      pt: "Misture tudo até ficar lindo e salve no seu álbum."
    },
    save: { en: "Save this style", pt: "Salvar penteado" },
    randomize: { en: "Shuffle", pt: "Sortear" },
    reset: { en: "Start over", pt: "Recomeçar" },
    nameYourStyle: { en: "Name your style", pt: "Dê um nome ao penteado" },
    saved: { en: "Saved to your lookbook!", pt: "Salvo no seu álbum!" },
    useMine: { en: "Use my styles in the picker", pt: "Usar meus penteados no sorteio" },
    deleteQ: { en: "Delete this style?", pt: "Apagar este penteado?" },

    gStart: { en: "Start", pt: "Começar" },
    gPlayAgain: { en: "Play again", pt: "Jogar de novo" },
    gClient: { en: "The client wants", pt: "A cliente quer" },
    gYours: { en: "Your work", pt: "Seu trabalho" },
    gDone: { en: "Done!", pt: "Pronto!" },
    gScore: { en: "Score", pt: "Pontos" },
    gRound: { en: "Client", pt: "Cliente" },
    gTime: { en: "Time", pt: "Tempo" },
    gPerfect: { en: "Perfect! ⭐⭐⭐", pt: "Perfeito! ⭐⭐⭐" },
    gClose: { en: "So close!", pt: "Quase!" },
    gOops: { en: "Not quite…", pt: "Quase lá…" },
    gOver: { en: "Salon closed!", pt: "Salão fechado!" },
    gFinal: { en: "Final score", pt: "Pontuação final" },
    gBest: { en: "Best", pt: "Recorde" },
    gRules: {
      en: "A client walks in with a photo. Rebuild that exact hairstyle with the buttons, then press Done. 5 clients per shift.",
      pt: "A cliente chega com uma foto. Monte o mesmo penteado com os botões e aperte Pronto. 5 clientes por turno."
    },
    mMoves: { en: "Moves", pt: "Jogadas" },
    mRules: {
      en: "Flip two cards. Find all the matching hairstyle pairs in as few moves as you can.",
      pt: "Vire duas cartas. Ache todos os pares de penteados com o menor número de jogadas."
    },
    mWin: { en: "All pairs found!", pt: "Todos os pares encontrados!" },

    yourName: { en: "Your name", pt: "Seu nome" },
    hairLength: { en: "Hair length", pt: "Comprimento do cabelo" },
    hairTexture: { en: "Hair type", pt: "Tipo de cabelo" },
    hairColor: { en: "Hair colour", pt: "Cor do cabelo" },
    skinTone: { en: "Skin tone", pt: "Tom de pele" },
    whereYouLive: { en: "Where you live", pt: "Onde você mora" },
    south: { en: "Southern hemisphere (Brazil)", pt: "Hemisfério sul (Brasil)" },
    north: { en: "Northern hemisphere", pt: "Hemisfério norte" },
    birthday: { en: "Birthday", pt: "Aniversário" },
    myDays: { en: "My own special days", pt: "Meus dias especiais" },
    myDaysHint: {
      en: "School photo day, a trip, a party… add them and they get their own hairstyle.",
      pt: "Foto da escola, viagem, festa… adicione e eles ganham um penteado só deles."
    },
    dayName: { en: "What is it?", pt: "O que é?" },
    addDay: { en: "Add day", pt: "Adicionar dia" },
    lengthShort: { en: "Short", pt: "Curto" },
    lengthMedium: { en: "Medium", pt: "Médio" },
    lengthLong: { en: "Long", pt: "Longo" },
    texStraight: { en: "Straight", pt: "Liso" },
    texWavy: { en: "Wavy", pt: "Ondulado" },
    texCurly: { en: "Curly", pt: "Cacheado" },
    texCoily: { en: "Coily", pt: "Crespo" },
    resetAll: { en: "Erase everything and start fresh", pt: "Apagar tudo e recomeçar" },
    resetQ: {
      en: "This erases your settings, saved styles and favourites. Sure?",
      pt: "Isso apaga seus ajustes, penteados salvos e favoritos. Tem certeza?"
    },

    oLength: { en: "Length", pt: "Comprimento" },
    oTexture: { en: "Texture", pt: "Textura" },
    oUpdo: { en: "Tied up", pt: "Preso" },
    oBraid: { en: "Braids", pt: "Tranças" },
    oBangs: { en: "Fringe", pt: "Franja" },
    oAcc: { en: "Accessory", pt: "Acessório" },
    oColor: { en: "Colour", pt: "Cor" },
    oAccColor: { en: "Accessory colour", pt: "Cor do acessório" },
    none: { en: "None", pt: "Nenhum" }
  };

  /* Component option labels used by the salon + game */
  const OPT_LABELS = {
    length: { short: UI.lengthShort, medium: UI.lengthMedium, long: UI.lengthLong },
    texture: { straight: UI.texStraight, wavy: UI.texWavy, curly: UI.texCurly, coily: UI.texCoily },
    updo: {
      none: { en: "Loose", pt: "Solto" },
      ponyHigh: { en: "High pony", pt: "Rabo alto" },
      ponyLow: { en: "Low pony", pt: "Rabo baixo" },
      ponySide: { en: "Side pony", pt: "Rabo de lado" },
      pigtails: { en: "Pigtails", pt: "Maria-chiquinha" },
      bunTop: { en: "Top bun", pt: "Coque alto" },
      bunsTwo: { en: "Two buns", pt: "Coquinhos" },
      bunLow: { en: "Low bun", pt: "Coque baixo" },
      halfUp: { en: "Half up", pt: "Meio preso" },
      knots: { en: "Little knots", pt: "Nozinhos" }
    },
    braid: {
      none: UI.none,
      one: { en: "One braid", pt: "Uma trança" },
      two: { en: "Two braids", pt: "Duas tranças" },
      crown: { en: "Crown braid", pt: "Trança coroa" },
      front: { en: "Front braid", pt: "Trança na frente" }
    },
    bangs: {
      none: UI.none,
      straight: { en: "Straight", pt: "Reta" },
      side: { en: "Side swept", pt: "De lado" },
      curtain: { en: "Curtain", pt: "Cortina" }
    },
    accessory: {
      none: UI.none,
      bow: { en: "Bow", pt: "Laço" },
      flower: { en: "Flowers", pt: "Flores" },
      headband: { en: "Headband", pt: "Tiara" },
      scrunchie: { en: "Scrunchie", pt: "Xuxinha" },
      tiara: { en: "Crown", pt: "Coroa" },
      ribbons: { en: "Ribbons", pt: "Fitas" },
      bandana: { en: "Bandana", pt: "Bandana" },
      clips: { en: "Hair clips", pt: "Presilhas" },
      feathers: { en: "Feathers", pt: "Penas" },
      glitter: { en: "Glitter", pt: "Glitter" },
      santa: { en: "Santa hat", pt: "Gorro de Natal" },
      spider: { en: "Spider", pt: "Aranha" },
      hearts: { en: "Hearts", pt: "Corações" },
      sunhat: { en: "Sun hat", pt: "Chapéu de sol" },
      strawhat: { en: "Straw hat", pt: "Chapéu de palha" }
    }
  };

  const TOOLS = {
    brush: { en: "a brush", pt: "uma escova" },
    comb: { en: "a comb", pt: "um pente" },
    elastic: { en: "hair elastics", pt: "elásticos" },
    scrunchie: { en: "a scrunchie", pt: "uma xuxinha" },
    pins: { en: "bobby pins", pt: "grampos" },
    spray: { en: "a water spray", pt: "borrifador de água" },
    cream: { en: "curl cream", pt: "creme para cachos" },
    ribbon: { en: "ribbons", pt: "fitas" },
    bow: { en: "a bow", pt: "um laço" },
    band: { en: "a headband", pt: "uma tiara" },
    flowers: { en: "fake flowers", pt: "flores de enfeite" },
    glitter: { en: "hair glitter", pt: "glitter de cabelo" },
    clips: { en: "hair clips", pt: "presilhas" },
    donut: { en: "a bun donut", pt: "uma rosquinha de coque" },
    patience: { en: "a pinch of patience", pt: "uma pitada de paciência" },
    helper: { en: "a grown-up helper", pt: "um adulto para ajudar" }
  };

  /* --------------------------------------------------------------- catalog */
  /* look = {length, texture, updo, braid, bangs, accessory, accColor} */
  const S = (id, en, pt, look, o) =>
    Object.assign({ id: id, n: { en: en, pt: pt }, look: look }, o);

  const STYLES = [
    S("classic-pony", "Classic Ponytail", "Rabo de cavalo clássico",
      { updo: "ponyHigh" },
      { d: 1, min: 3, tags: ["everyday", "school", "sporty"], len: ["medium", "long"],
        tools: ["brush", "elastic"],
        steps: [
          ["Brush all the tangles out, from the ends upwards.", "Escove todos os nós, começando pelas pontas."],
          ["Tip your head back a little and gather the hair at the crown.", "Incline a cabeça para trás e junte o cabelo no alto."],
          ["Hold the bunch tight with one hand so nothing escapes.", "Segure firme com uma mão para nada escapar."],
          ["Wrap the elastic around three or four times.", "Enrole o elástico três ou quatro vezes."],
          ["Pull the tail apart gently to tighten it up.", "Puxe o rabo em duas partes para apertar."]
        ],
        tip: ["Slightly damp hair is much easier to catch.", "Cabelo um pouco úmido é bem mais fácil de prender."] }),

    S("low-pony", "Low Ponytail", "Rabo de cavalo baixo",
      { updo: "ponyLow" },
      { d: 1, min: 3, tags: ["everyday", "school", "cozy"], len: ["medium", "long"],
        tools: ["brush", "elastic"],
        steps: [
          ["Brush the hair straight down.", "Escove o cabelo todo para baixo."],
          ["Gather it at the nape of the neck, low and level.", "Junte na nuca, bem baixinho e reto."],
          ["Twist the bunch once so it stays smooth.", "Dê uma torcidinha para ficar liso."],
          ["Tie the elastic snugly, not tight enough to hurt.", "Prenda o elástico firme, sem apertar demais."]
        ],
        tip: ["Great for windy days — nothing blows in your face.", "Ótimo para dias de vento — nada voa no rosto."] }),

    S("side-pony", "Side Ponytail", "Rabo de lado",
      { updo: "ponySide" },
      { d: 1, min: 4, tags: ["play", "party", "everyday"], len: ["medium", "long"],
        tools: ["brush", "elastic", "scrunchie"],
        steps: [
          ["Part the hair on one side, quite deep.", "Faça uma risca bem marcada de um lado."],
          ["Sweep everything over your favourite shoulder.", "Jogue tudo por cima do ombro preferido."],
          ["Hold it just below the ear.", "Segure logo abaixo da orelha."],
          ["Tie with an elastic, then hide it with a scrunchie.", "Prenda com elástico e esconda com a xuxinha."]
        ],
        tip: ["Leave two little strands loose in front.", "Deixe dois fiozinhos soltos na frente."] }),

    S("bubble-pony", "Bubble Ponytail", "Rabo de bolhas",
      { updo: "ponyHigh", tail: "bubble", accessory: "scrunchie", accColor: "pink" },
      { d: 2, min: 8, tags: ["party", "play", "birthday"], len: ["long"],
        tools: ["brush", "elastic", "patience"],
        steps: [
          ["Start with a high ponytail.", "Comece com um rabo de cavalo alto."],
          ["Tie another elastic a few fingers down the tail.", "Prenda outro elástico alguns dedos abaixo."],
          ["Puff the hair between the two elastics into a bubble.", "Afofe o cabelo entre os dois elásticos como uma bolha."],
          ["Repeat all the way down: tie, puff, tie, puff.", "Repita até o fim: prende, afofa, prende, afofa."],
          ["Even out the bubbles so they are all the same size.", "Deixe as bolhas todas do mesmo tamanho."]
        ],
        tip: ["Use elastics in rainbow colours, one per bubble.", "Use elásticos coloridos, um por bolha."] }),

    S("pigtails", "Pigtails", "Maria-chiquinha",
      { updo: "pigtails" },
      { d: 1, min: 5, tags: ["school", "play", "everyday"], len: ["short", "medium", "long"],
        tools: ["brush", "comb", "elastic"],
        steps: [
          ["Comb a straight part right down the middle.", "Faça uma risca reta no meio com o pente."],
          ["Hold one half out of the way with a clip.", "Prenda um lado com uma presilha para não atrapalhar."],
          ["Tie the first side above the ear.", "Prenda o primeiro lado acima da orelha."],
          ["Do the same on the other side, at the same height.", "Faça igual do outro lado, na mesma altura."],
          ["Check in the mirror that both are level.", "Confira no espelho se os dois estão iguais."]
        ],
        tip: ["Look from behind — that is where crooked parts show.", "Olhe por trás — é lá que a risca torta aparece."] }),

    S("space-buns", "Double Buns", "Coquinhos duplos",
      { updo: "bunsTwo" },
      { d: 2, min: 9, tags: ["party", "play", "festival", "carnival"], len: ["short", "medium", "long"],
        tools: ["brush", "elastic", "pins"],
        steps: [
          ["Part the hair down the middle.", "Divida o cabelo no meio."],
          ["Make two high ponytails, one on each side.", "Faça dois rabinhos altos, um de cada lado."],
          ["Twist the first tail around itself like a snail.", "Torça o primeiro rabinho em volta de si como um caracol."],
          ["Pin the coil down with two or three bobby pins.", "Prenda o rolinho com dois ou três grampos."],
          ["Repeat on the other side and pull a few wisps loose.", "Repita do outro lado e solte alguns fiozinhos."]
        ],
        tip: ["Buns never have to be perfect — messy looks cool.", "Coque não precisa ser perfeito — bagunçado fica legal."] }),

    S("top-knot", "Top Knot", "Coque alto",
      { updo: "bunTop" },
      { d: 2, min: 6, tags: ["sporty", "school", "everyday"], len: ["medium", "long"],
        tools: ["brush", "elastic", "pins"],
        steps: [
          ["Brush everything up to the very top of your head.", "Escove tudo para o alto da cabeça."],
          ["Tie a tight high ponytail.", "Prenda um rabo de cavalo bem alto."],
          ["Twist the tail into a rope and wind it around the base.", "Torça o rabo como uma corda e enrole na base."],
          ["Tuck the end under and pin it.", "Esconda a ponta embaixo e prenda com grampo."]
        ],
        tip: ["Perfect for sports — it will not move all day.", "Perfeito para esportes — não sai do lugar."] }),

    S("ballerina-bun", "Ballerina Bun", "Coque de bailarina",
      { updo: "bunTop", accessory: "tiara", accColor: "gold" },
      { d: 3, min: 12, tags: ["fancy", "party", "dance"], len: ["long"],
        tools: ["brush", "elastic", "donut", "pins", "spray"],
        steps: [
          ["Spray a little water to smooth every flyaway.", "Borrife água para alisar os fiozinhos rebeldes."],
          ["Make a very smooth high ponytail.", "Faça um rabo de cavalo bem liso e alto."],
          ["Slide the bun donut over the tail.", "Passe a rosquinha de coque pelo rabo."],
          ["Spread the hair evenly over the donut and cover it.", "Espalhe o cabelo por toda a rosquinha, cobrindo tudo."],
          ["Tuck the ends around the base and pin all the way round.", "Enrole as pontas na base e grampeie em volta."],
          ["Add the little crown at the front of the bun.", "Coloque a coroinha na frente do coque."]
        ],
        tip: ["Ask a grown-up for the pinning part.", "Peça ajuda de um adulto na hora dos grampos."],
        helper: true }),

    S("low-bun", "Low Bun", "Coque baixo",
      { updo: "bunLow" },
      { d: 2, min: 7, tags: ["fancy", "school", "cozy"], len: ["medium", "long"],
        tools: ["brush", "elastic", "pins"],
        steps: [
          ["Brush the hair back into a low ponytail.", "Escove tudo para um rabo baixo."],
          ["Twist the tail gently into a rope.", "Torça o rabo virando uma corda."],
          ["Coil the rope into a circle at the nape.", "Enrole a corda em círculo na nuca."],
          ["Pin the circle in three places, like a clock.", "Grampeie em três pontos, como um relógio."]
        ],
        tip: ["Looks lovely with a ribbon tied around it.", "Fica lindo com uma fita amarrada em volta."] }),

    S("messy-bun", "Messy Bun", "Coque bagunçado",
      { updo: "bunTop", texture: "wavy" },
      { d: 1, min: 3, tags: ["everyday", "lazy", "rain", "cozy"], len: ["medium", "long"],
        tools: ["scrunchie"],
        steps: [
          ["Do not brush. Really — this one likes messy hair.", "Não escove. É sério — este gosta de cabelo bagunçado."],
          ["Gather everything loosely on top.", "Junte tudo frouxinho no alto."],
          ["Twist once and loop it through the scrunchie.", "Torça uma vez e passe pela xuxinha."],
          ["Pull out a few strands on purpose.", "Puxe alguns fios de propósito."]
        ],
        tip: ["The three-minute hairstyle for late mornings.", "O penteado de três minutos para manhãs atrasadas."] }),

    S("half-up", "Half Up Half Down", "Meio preso",
      { updo: "halfUp" },
      { d: 1, min: 4, tags: ["everyday", "school", "play"], len: ["short", "medium", "long"],
        tools: ["brush", "elastic"],
        steps: [
          ["Brush all the hair back.", "Escove todo o cabelo para trás."],
          ["Take the top half, from ear to ear.", "Pegue a metade de cima, de orelha a orelha."],
          ["Tie it at the back of the head.", "Prenda atrás da cabeça."],
          ["Leave the bottom half hanging free.", "Deixe a metade de baixo solta."]
        ],
        tip: ["Best of both worlds: hair down, face clear.", "O melhor dos dois mundos: cabelo solto e rosto livre."] }),

    S("half-up-bow", "Half Up with a Bow", "Meio preso com laço",
      { updo: "halfUp", accessory: "bow", accColor: "pink" },
      { d: 1, min: 5, tags: ["party", "birthday", "school"], len: ["short", "medium", "long"],
        tools: ["brush", "elastic", "bow"],
        steps: [
          ["Make a simple half-up ponytail.", "Faça um meio preso simples."],
          ["Hide the elastic with a small strand of hair.", "Esconda o elástico com uma mecha de cabelo."],
          ["Clip the bow right on top of the elastic.", "Prenda o laço bem em cima do elástico."],
          ["Straighten the bow so both loops match.", "Ajeite o laço para as duas alças ficarem iguais."]
        ],
        tip: ["Match the bow to your socks. Always a good move.", "Combine o laço com a meia. Sempre funciona."] }),

    S("two-braids", "Two Braids", "Duas tranças",
      { braid: "two" },
      { d: 2, min: 10, tags: ["school", "sporty", "beach", "everyday"], len: ["medium", "long"],
        tools: ["comb", "elastic", "patience"],
        steps: [
          ["Part the hair down the middle.", "Divida o cabelo no meio."],
          ["Split one side into three equal strands.", "Separe um lado em três mechas iguais."],
          ["Cross the right strand over the middle, then the left over the middle.", "Passe a mecha da direita sobre o meio, depois a da esquerda."],
          ["Keep crossing all the way to the ends.", "Continue cruzando até as pontas."],
          ["Tie it off and do the other side the same way.", "Prenda a ponta e faça o outro lado igual."]
        ],
        tip: ["Braids sleep well — wake up with soft waves.", "Trança dorme bem — você acorda com ondas."] }),

    S("single-braid", "One Long Braid", "Trança única",
      { braid: "one" },
      { d: 2, min: 7, tags: ["everyday", "school", "cozy"], len: ["long"],
        tools: ["comb", "elastic"],
        steps: [
          ["Brush everything to the back.", "Escove tudo para trás."],
          ["Divide into three equal strands.", "Divida em três mechas iguais."],
          ["Cross outside strands over the middle, one after the other.", "Cruze as mechas de fora sobre a do meio, uma de cada vez."],
          ["Keep the strands tight and even.", "Mantenha as mechas firmes e iguais."],
          ["Tie the end and give it a little tug to fluff it.", "Prenda a ponta e dê uma puxadinha para afofar."]
        ],
        tip: ["Count out loud: right, left, right, left.", "Conte em voz alta: direita, esquerda, direita, esquerda."] }),

    S("french-braid", "French Braid", "Trança francesa",
      { braid: "front" },
      { d: 3, min: 14, tags: ["school", "fancy", "sporty"], len: ["medium", "long"],
        tools: ["comb", "elastic", "spray", "patience", "helper"],
        steps: [
          ["Take a small section at the top of the head.", "Pegue uma mecha pequena no alto da cabeça."],
          ["Split it into three and start a normal braid.", "Divida em três e comece uma trança normal."],
          ["Each time you cross, add a little new hair to that strand.", "A cada cruzada, junte um pouco de cabelo novo na mecha."],
          ["Keep adding hair until you reach the neck.", "Continue juntando até chegar no pescoço."],
          ["Finish with a plain braid and tie it.", "Termine com trança comum e prenda."]
        ],
        tip: ["Slow is fast. Small sections look neatest.", "Devagar é mais rápido. Mechas pequenas ficam mais bonitas."],
        helper: true }),

    S("fishtail", "Fishtail Braid", "Trança espinha de peixe",
      { braid: "one", texture: "wavy" },
      { d: 3, min: 15, tags: ["fancy", "party", "beach"], len: ["long"],
        tools: ["comb", "elastic", "patience"],
        steps: [
          ["Split the hair into two halves only.", "Divida o cabelo em apenas duas partes."],
          ["Take a thin strand from the outside of the left half.", "Pegue um fio fininho da beirada da parte esquerda."],
          ["Cross it over to join the right half.", "Passe ele para a parte direita."],
          ["Do the same from the right side over to the left.", "Faça o mesmo da direita para a esquerda."],
          ["Keep swapping thin strands until you run out of hair.", "Continue trocando fios finos até acabar o cabelo."]
        ],
        tip: ["Thinner strands make a prettier pattern.", "Mechas mais finas deixam o desenho mais bonito."] }),

    S("crown-braid", "Crown Braid", "Trança coroa",
      { braid: "crown" },
      { d: 3, min: 16, tags: ["fancy", "festival", "party", "spring"], len: ["long"],
        tools: ["comb", "elastic", "pins", "helper"],
        steps: [
          ["Part the hair down the middle.", "Divida o cabelo no meio."],
          ["Braid each side loosely from the temple down.", "Trance cada lado frouxinho, da têmpora para baixo."],
          ["Lift the left braid over the top of your head.", "Leve a trança esquerda por cima da cabeça."],
          ["Pin it behind the right ear.", "Prenda atrás da orelha direita."],
          ["Do the same with the right braid, and tuck the ends away.", "Faça o mesmo com a direita e esconda as pontas."]
        ],
        tip: ["Tuck a small flower where the braids meet.", "Coloque uma flor onde as tranças se encontram."],
        helper: true }),

    S("braid-ribbons", "Ribbon Braids", "Tranças com fitas",
      { braid: "two", accessory: "ribbons", accColor: "red" },
      { d: 2, min: 12, tags: ["festival", "party", "junina"], len: ["medium", "long"],
        tools: ["comb", "elastic", "ribbon"],
        steps: [
          ["Part in the middle and split into two sides.", "Faça a risca no meio e separe dois lados."],
          ["Tie a long ribbon at the top of the first section.", "Amarre uma fita comprida no alto da primeira mecha."],
          ["Braid with the ribbon as if it were a fourth strand.", "Trance com a fita como se fosse mais uma mecha."],
          ["Tie the ribbon in a bow at the end.", "Amarre a fita em laço na ponta."],
          ["Repeat on the other side with a different colour.", "Repita do outro lado com outra cor."]
        ],
        tip: ["Festa Junina rule: the louder the colours, the better.", "Regra de Festa Junina: quanto mais colorido, melhor."] }),

    S("beach-waves", "Beach Waves", "Ondas de praia",
      { texture: "wavy", length: "long" },
      { d: 1, min: 6, tags: ["beach", "summer", "play", "everyday"], len: ["short", "medium", "long"],
        tools: ["spray", "cream"],
        steps: [
          ["Dampen the hair with the water spray.", "Umedeça o cabelo com o borrifador."],
          ["Work a little curl cream through with your fingers.", "Passe um pouco de creme com os dedos."],
          ["Scrunch handfuls of hair upwards towards your head.", "Amasse mechas para cima, na direção da cabeça."],
          ["Let it dry by itself — no brushing after!", "Deixe secar sozinho — nada de escovar depois!"]
        ],
        tip: ["Braid it while damp, undo when dry, for extra waves.", "Trance úmido e solte seco para mais ondas."] }),

    S("afro-puff", "Afro Puff", "Black power preso",
      { texture: "coily", updo: "bunTop" },
      { d: 1, min: 5, tags: ["everyday", "school", "sporty"], len: ["short", "medium", "long"],
        tex: ["curly", "coily"],
        tools: ["comb", "cream", "scrunchie"],
        steps: [
          ["Spritz the hair with water so it is soft.", "Borrife água para amaciar o cabelo."],
          ["Smooth a little cream over the sides.", "Passe um pouco de creme nas laterais."],
          ["Gather everything up with a soft scrunchie.", "Junte tudo com uma xuxinha macia."],
          ["Fluff the puff with your fingers or a pick.", "Afofe o puff com os dedos ou o garfinho."]
        ],
        tip: ["Never comb dry coils — always damp and soft.", "Nunca penteie crespo seco — sempre úmido e macio."] }),

    S("afro-out", "Afro Out", "Black power solto",
      { texture: "coily" },
      { d: 1, min: 6, tags: ["everyday", "party", "play"], len: ["short", "medium", "long"],
        tex: ["curly", "coily"],
        tools: ["cream", "spray", "comb"],
        steps: [
          ["Wet the hair lightly all over.", "Molhe levemente todo o cabelo."],
          ["Rub curl cream between your palms and press it in.", "Esfregue o creme nas mãos e aperte no cabelo."],
          ["Separate the curls gently with your fingers.", "Separe os cachos com os dedos, sem pressa."],
          ["Lift from the roots with a hair pick for volume.", "Levante da raiz com o garfinho para dar volume."]
        ],
        tip: ["Big hair, big day. Shake it and go.", "Cabelo grande, dia grande. Sacode e vai."] }),

    S("bantu-knots", "Little Knots", "Nozinhos",
      { texture: "coily", updo: "knots" },
      { d: 3, min: 20, tags: ["party", "festival", "play"], len: ["short", "medium", "long"],
        tex: ["curly", "coily"],
        tools: ["comb", "cream", "elastic", "patience", "helper"],
        steps: [
          ["Part the hair into small squares, like a chessboard.", "Divida o cabelo em quadradinhos, como um tabuleiro."],
          ["Twist one section tightly from root to tip.", "Torça uma seção bem firme da raiz à ponta."],
          ["Keep twisting until it coils into a little knot.", "Continue torcendo até virar um nozinho."],
          ["Tuck the end underneath and secure it.", "Enfie a ponta embaixo e prenda."],
          ["Do every section — put on music, it takes a while.", "Faça todas as seções — coloque música, demora um pouco."]
        ],
        tip: ["Undo them the next day for amazing curls.", "Desmanche no dia seguinte para cachos incríveis."],
        helper: true }),

    S("headband-down", "Hair Down with a Headband", "Cabelo solto com tiara",
      { accessory: "headband", accColor: "purple" },
      { d: 1, min: 2, tags: ["everyday", "lazy", "school"], len: ["short", "medium", "long"],
        tools: ["brush", "band"],
        steps: [
          ["Brush the hair smooth and leave it down.", "Escove o cabelo e deixe solto."],
          ["Slide the headband on from the front.", "Coloque a tiara pela frente."],
          ["Push it back until it sits behind your ears.", "Empurre até ficar atrás das orelhas."],
          ["Pull a little hair forward over the band edge.", "Puxe um pouco de cabelo sobre a beirada da tiara."]
        ],
        tip: ["The two-minute rescue for very sleepy mornings.", "O salvamento de dois minutos para manhãs sonolentas."] }),

    S("flower-crown", "Flower Crown", "Coroa de flores",
      { accessory: "flower", accColor: "pink", texture: "wavy" },
      { d: 2, min: 8, tags: ["spring", "party", "festival", "birthday"], len: ["short", "medium", "long"],
        tools: ["brush", "flowers", "clips"],
        steps: [
          ["Brush the hair and leave it mostly loose.", "Escove e deixe o cabelo quase todo solto."],
          ["Take two thin strands from the front.", "Pegue duas mechas finas da frente."],
          ["Pin them together at the back like a little arch.", "Prenda as duas atrás, formando um arquinho."],
          ["Clip flowers along the arch, biggest first.", "Prenda flores ao longo do arco, as maiores primeiro."],
          ["Add smaller flowers to fill the gaps.", "Coloque flores menores nos espaços."]
        ],
        tip: ["Odd numbers of flowers look better than even.", "Número ímpar de flores fica mais bonito que par."] }),

    S("bandana", "Bandana Day", "Dia de bandana",
      { accessory: "bandana", accColor: "red" },
      { d: 1, min: 3, tags: ["rain", "lazy", "beach", "play"], len: ["short", "medium", "long"],
        tools: ["brush"],
        steps: [
          ["Fold the bandana into a long triangle.", "Dobre a bandana num triângulo comprido."],
          ["Lay the wide edge along your hairline.", "Coloque a parte larga na linha do cabelo."],
          ["Tie the two ends behind your head.", "Amarre as duas pontas atrás da cabeça."],
          ["Tuck the pointy bit underneath.", "Esconda a ponta embaixo."]
        ],
        tip: ["Saves any bad hair day in ten seconds.", "Salva qualquer dia de cabelo ruim em dez segundos."] }),

    S("bob-sleek", "Sleek and Shiny", "Liso e brilhante",
      { length: "short", texture: "straight", bangs: "straight" },
      { d: 1, min: 4, tags: ["everyday", "school", "fancy"], len: ["short", "medium"],
        tools: ["brush", "comb", "spray"],
        steps: [
          ["Mist the hair very lightly with water.", "Borrife bem pouquinho de água."],
          ["Brush from the roots down, again and again.", "Escove da raiz para baixo, várias vezes."],
          ["Comb the fringe straight down over the forehead.", "Penteie a franja reta sobre a testa."],
          ["Tuck one side behind an ear.", "Coloque um lado atrás da orelha."]
        ],
        tip: ["Brushing 20 times makes it shine. Count them.", "Escovar 20 vezes deixa brilhando. Conte."] }),

    S("clips-galore", "All the Clips", "Muitas presilhas",
      { accessory: "clips", accColor: "mint" },
      { d: 1, min: 5, tags: ["play", "party", "everyday", "birthday"], len: ["short", "medium", "long"],
        tools: ["clips", "comb"],
        steps: [
          ["Leave the hair loose or in a half-up.", "Deixe o cabelo solto ou meio preso."],
          ["Line up clips along one side, evenly spaced.", "Alinhe presilhas de um lado, bem espaçadas."],
          ["Add a second row underneath in another colour.", "Faça uma segunda fileira embaixo com outra cor."],
          ["Put one surprise clip somewhere silly.", "Coloque uma presilha surpresa num lugar engraçado."]
        ],
        tip: ["Rainbow order is the most satisfying order.", "Na ordem do arco-íris fica mais gostoso de ver."] }),

    S("carnival-glitter", "Carnival Glitter Buns", "Coquinhos de Carnaval",
      { updo: "bunsTwo", accessory: "glitter", accColor: "gold" },
      { d: 2, min: 12, tags: ["carnival", "party", "festival"], len: ["medium", "long"],
        tools: ["brush", "elastic", "pins", "glitter"],
        steps: [
          ["Part the hair in the middle and make two high buns.", "Divida no meio e faça dois coques altos."],
          ["Pin each bun so it holds through the whole parade.", "Grampeie bem para aguentar o desfile inteiro."],
          ["Press glitter gel along the parting.", "Passe gel com glitter na risca."],
          ["Dust more glitter on the buns themselves.", "Jogue mais glitter nos coques."],
          ["Shake your head. If glitter flies, it is enough.", "Balance a cabeça. Se voar glitter, está bom."]
        ],
        tip: ["Glitter goes on the hair, not in the eyes!", "Glitter no cabelo, nunca nos olhos!"] }),

    S("feather-crown", "Feather Headdress", "Penacho de Carnaval",
      { accessory: "feathers", accColor: "purple", texture: "wavy" },
      { d: 2, min: 10, tags: ["carnival", "party", "festival"], len: ["short", "medium", "long"],
        tools: ["band", "clips", "glitter"],
        steps: [
          ["Leave the hair big and loose.", "Deixe o cabelo grande e solto."],
          ["Fix a headband firmly behind the ears.", "Prenda a tiara firme atrás das orelhas."],
          ["Clip the tallest feathers at the back first.", "Prenda as penas mais altas atrás primeiro."],
          ["Fill the front with shorter feathers.", "Preencha a frente com penas menores."],
          ["Check it holds when you dance. Then dance.", "Veja se aguenta dançar. Depois dance."]
        ],
        tip: ["Carnival hair should be visible from far away.", "Cabelo de Carnaval tem que ser visto de longe."] }),

    S("junina-braids", "Festa Junina Braids", "Tranças de Festa Junina",
      { braid: "two", accessory: "strawhat", accColor: "gold" },
      { d: 2, min: 12, tags: ["junina", "festival", "party"], len: ["medium", "long"],
        tools: ["comb", "elastic", "ribbon"],
        steps: [
          ["Make two braids, one on each side.", "Faça duas tranças, uma de cada lado."],
          ["Tie each one off with a bright ribbon.", "Amarre cada uma com uma fita colorida."],
          ["Draw freckles on your cheeks — it is the law.", "Desenhe sardinhas no rosto — é a lei."],
          ["Put the straw hat on over the top.", "Coloque o chapéu de palha por cima."]
        ],
        tip: ["Braids should stick out from under the hat.", "As tranças têm que aparecer embaixo do chapéu."] }),

    S("christmas-braids", "Christmas Ribbon Braids", "Tranças de Natal",
      { braid: "two", accessory: "santa", accColor: "red" },
      { d: 2, min: 12, tags: ["christmas", "party", "festival"], len: ["medium", "long"],
        tools: ["comb", "elastic", "ribbon"],
        steps: [
          ["Braid two sides with red and white ribbons.", "Trance dois lados com fitas vermelha e branca."],
          ["Twist the ribbons like candy canes as you go.", "Torça as fitas como bengalinhas doces."],
          ["Tie big bows at the ends.", "Faça laços grandes nas pontas."],
          ["Add the Santa hat right on top.", "Coloque o gorro de Natal por cima."]
        ],
        tip: ["Works with a jingle bell clipped on. Loudly.", "Fica ótimo com um guizo preso. Bem barulhento."] }),

    S("newyear-sparkle", "New Year Sparkle Bun", "Coque de Réveillon",
      { updo: "bunLow", accessory: "glitter", accColor: "white" },
      { d: 2, min: 10, tags: ["newyear", "fancy", "party"], len: ["medium", "long"],
        tools: ["brush", "elastic", "pins", "glitter"],
        steps: [
          ["Brush everything into a smooth low bun.", "Escove tudo num coque baixo bem liso."],
          ["Pin it neatly all the way around.", "Grampeie em volta, bem arrumadinho."],
          ["Wrap a silver or white ribbon around the base.", "Amarre uma fita branca ou prateada na base."],
          ["Finish with silver glitter on top.", "Finalize com glitter prateado por cima."]
        ],
        tip: ["Wear white — and make a wish at midnight.", "Vista branco — e faça um pedido à meia-noite."] }),

    S("spider-bun", "Spooky Spider Bun", "Coque da aranha",
      { updo: "bunTop", accessory: "spider", accColor: "black" },
      { d: 2, min: 11, tags: ["halloween", "party", "play"], len: ["medium", "long"],
        tools: ["brush", "elastic", "pins"],
        steps: [
          ["Make a big tight top bun.", "Faça um coque alto bem firme."],
          ["Pull thin strands from the bun out like web threads.", "Puxe fios finos do coque como teias."],
          ["Pin the threads down so they stay spread out.", "Prenda os fios para ficarem abertos."],
          ["Sit the toy spider right in the middle.", "Coloque a aranhinha bem no meio."]
        ],
        tip: ["Say boo to someone. That is part of the hairstyle.", "Assuste alguém. Faz parte do penteado."] }),

    S("heart-braid", "Heart Braid", "Trança de coração",
      { braid: "crown", accessory: "hearts", accColor: "pink" },
      { d: 3, min: 16, tags: ["valentine", "fancy", "party"], len: ["medium", "long"],
        tools: ["comb", "elastic", "pins", "clips", "helper"],
        steps: [
          ["Part the hair into two halves.", "Divida o cabelo em duas metades."],
          ["Braid each side curving inwards like half a heart.", "Trance cada lado curvando para dentro, como meio coração."],
          ["Join the two braids at the bottom point.", "Junte as duas tranças na ponta de baixo."],
          ["Pin the shape so the heart holds.", "Grampeie para o coração ficar firme."],
          ["Clip tiny hearts around the edges.", "Prenda coraçõezinhos nas bordas."]
        ],
        tip: ["Stand in front of a mirror with a second mirror behind.", "Use dois espelhos para ver atrás."],
        helper: true }),

    S("birthday-crown", "Birthday Crown Hair", "Cabelo de aniversário",
      { updo: "halfUp", accessory: "tiara", accColor: "gold", texture: "wavy" },
      { d: 2, min: 9, tags: ["birthday", "party", "fancy"], len: ["short", "medium", "long"],
        tools: ["brush", "elastic", "clips", "glitter"],
        steps: [
          ["Give the hair a good brush until it shines.", "Escove bem até brilhar."],
          ["Tie a half-up so the crown has something to grip.", "Faça um meio preso para a coroa ter onde firmar."],
          ["Sit the crown on top and clip it at both sides.", "Coloque a coroa e prenda nos dois lados."],
          ["Add a pinch of glitter, because birthday.", "Coloque um tiquinho de glitter, porque é aniversário."]
        ],
        tip: ["Today you are the most important person. Dress the hair like it.", "Hoje você é a pessoa mais importante. Penteie assim."] }),

    S("brazil-ribbons", "Green and Yellow Ribbons", "Fitas verde e amarela",
      { updo: "pigtails", accessory: "ribbons", accColor: "green" },
      { d: 2, min: 9, tags: ["brazil", "sporty", "party", "festival"], len: ["medium", "long"],
        tools: ["comb", "elastic", "ribbon"],
        steps: [
          ["Part the hair in the middle.", "Faça a risca no meio."],
          ["Tie two ponytails, one each side.", "Prenda dois rabinhos, um de cada lado."],
          ["Wind a green ribbon around one, yellow around the other.", "Enrole fita verde num e amarela no outro."],
          ["Finish both with big bows.", "Termine os dois com laços grandes."]
        ],
        tip: ["Blue and white ribbons work too — full flag.", "Fitas azul e branca também valem — bandeira completa."] }),

    S("sunhat-waves", "Sun Hat and Waves", "Ondas com chapéu de sol",
      { texture: "wavy", accessory: "sunhat", accColor: "gold" },
      { d: 1, min: 5, tags: ["beach", "summer", "lazy"], len: ["medium", "long"],
        tools: ["spray", "cream"],
        steps: [
          ["Damp hair, a little cream, scrunch the ends.", "Cabelo úmido, um pouco de creme, amasse as pontas."],
          ["Let it dry in the sun for a few minutes.", "Deixe secar no sol por alguns minutos."],
          ["Put the hat on and pull the waves out at the sides.", "Coloque o chapéu e puxe as ondas pelos lados."],
          ["Do not brush under the hat. Ever.", "Não escove embaixo do chapéu. Nunca."]
        ],
        tip: ["Rinse salt and chlorine out the same day.", "Tire o sal e o cloro no mesmo dia."] }),

    S("rainy-bun", "Rainy Day Bun", "Coque de dia de chuva",
      { updo: "bunTop", texture: "curly", accessory: "scrunchie", accColor: "blue" },
      { d: 1, min: 4, tags: ["rain", "lazy", "cozy", "everyday"], len: ["medium", "long"],
        tools: ["scrunchie", "cream"],
        steps: [
          ["Do not fight the frizz. It always wins.", "Não lute contra o frizz. Ele sempre ganha."],
          ["Smooth a drop of cream over the top layer.", "Passe uma gotinha de creme por cima."],
          ["Pile everything into a high bun with the scrunchie.", "Junte tudo num coque alto com a xuxinha."],
          ["Hood up, and off you go.", "Capuz na cabeça e pode ir."]
        ],
        tip: ["High buns stay dry under a hood.", "Coque alto fica seco embaixo do capuz."] }),

    S("winter-cozy-braid", "Cosy Side Braid", "Trança lateral aconchegante",
      { braid: "one", updo: "ponySide", texture: "wavy" },
      { d: 2, min: 9, tags: ["cozy", "winter", "everyday", "school"], len: ["medium", "long"],
        tools: ["brush", "elastic"],
        steps: [
          ["Sweep all the hair over one shoulder.", "Jogue todo o cabelo sobre um ombro."],
          ["Braid it loosely, right down the front.", "Trance frouxinho, pela frente."],
          ["Tie the end and squish the braid to make it fatter.", "Prenda a ponta e amasse a trança para engordar."],
          ["Tug little loops out along the sides.", "Puxe pequenas alças pelos lados."]
        ],
        tip: ["Loose braids look warmer than tight ones.", "Trança frouxa parece mais quentinha que apertada."] }),

    S("spring-half-flowers", "Spring Half-Up with Flowers", "Meio preso com flores",
      { updo: "halfUp", accessory: "flower", accColor: "mint", texture: "wavy" },
      { d: 2, min: 8, tags: ["spring", "party", "school"], len: ["short", "medium", "long"],
        tools: ["brush", "elastic", "flowers", "clips"],
        steps: [
          ["Make a soft half-up ponytail.", "Faça um meio preso macio."],
          ["Twist the loose top hair before you tie it.", "Torça o cabelo de cima antes de prender."],
          ["Tuck small flowers into the twist.", "Enfie flores pequenas na torção."],
          ["Leave the rest of the hair wavy and free.", "Deixe o resto ondulado e solto."]
        ],
        tip: ["Pick flowers that will survive a whole school day.", "Escolha flores que aguentem o dia inteiro."] }),

    S("sporty-two-cornrows", "Two Tight Braids", "Duas tranças raiz",
      { braid: "two", texture: "coily" },
      { d: 3, min: 18, tags: ["sporty", "school", "everyday"], len: ["short", "medium", "long"],
        tex: ["curly", "coily", "wavy"],
        tools: ["comb", "cream", "elastic", "patience", "helper"],
        steps: [
          ["Part the hair down the middle, very straight.", "Faça a risca no meio, bem reta."],
          ["Start at the hairline with three tiny strands.", "Comece na linha do cabelo com três mechinhas."],
          ["Braid downwards close to the scalp, adding hair each time.", "Trance rente ao couro, juntando cabelo a cada volta."],
          ["Follow the curve of the head to the nape.", "Acompanhe a curva da cabeça até a nuca."],
          ["Finish the ends loose and tie them.", "Termine as pontas soltas e prenda."]
        ],
        tip: ["Not tight enough to hurt — never pull the edges.", "Nunca apertado a ponto de doer — cuidado com as beiradas."],
        helper: true }),

    S("pony-ribbon-wrap", "Ribbon Wrapped Pony", "Rabo enrolado com fita",
      { updo: "ponyHigh", accessory: "ribbons", accColor: "purple" },
      { d: 2, min: 8, tags: ["party", "fancy", "birthday", "school"], len: ["long"],
        tools: ["brush", "elastic", "ribbon"],
        steps: [
          ["Tie a high ponytail.", "Prenda um rabo de cavalo alto."],
          ["Tie the ribbon at the base with a knot.", "Amarre a fita na base com um nó."],
          ["Wind the ribbon down the tail in a spiral.", "Enrole a fita em espiral pelo rabo."],
          ["Tie a bow a few fingers from the ends.", "Faça um laço alguns dedos antes das pontas."]
        ],
        tip: ["Satin ribbon slips — grosgrain holds better.", "Fita de cetim escorrega — a de gorgurão segura melhor."] }),
    S("palm-sprout", "Palm Tree Sprout", "Palmeirinha",
      { updo: "ponyHigh", accessory: "scrunchie", accColor: "mint" },
      { d: 1, min: 2, tags: ["play", "everyday", "school", "sporty"], len: ["short", "medium"],
        tools: ["comb", "elastic", "scrunchie"],
        steps: [
          ["Gather just the top of the hair, above the ears.", "Junte só a parte de cima, acima das orelhas."],
          ["Hold it straight up like a little palm tree.", "Segure tudo para cima, como uma palmeirinha."],
          ["Wrap a small soft elastic twice.", "Enrole um elástico pequeno duas vezes."],
          ["Fluff the top so it stands up proudly.", "Afofe a pontinha para ela ficar em pé."]
        ],
        tip: ["Best hairstyle in the world for short hair.", "O melhor penteado do mundo para cabelo curto."] }),

    S("twisty-pins", "Twisty Pins", "Torcidinhas com presilha",
      { braid: "front", accessory: "clips", accColor: "gold" },
      { d: 1, min: 5, tags: ["school", "everyday", "fancy", "party"], len: ["short", "medium", "long"],
        tools: ["comb", "clips", "spray"],
        steps: [
          ["Take a strand at the front, above one eyebrow.", "Pegue uma mecha na frente, acima da sobrancelha."],
          ["Twist it backwards, away from your face.", "Torça para trás, longe do rosto."],
          ["Pin it behind your ear with a pretty clip.", "Prenda atrás da orelha com uma presilha bonita."],
          ["Do the same on the other side.", "Faça o mesmo do outro lado."]
        ],
        tip: ["Twist away from your face, never towards it.", "Torça sempre para longe do rosto, nunca para dentro."] }),

    S("short-side-part", "Sharp Side Part", "Risca de lado",
      { bangs: "side", accessory: "clips", accColor: "pink" },
      { d: 1, min: 3, tags: ["school", "everyday", "fancy"], len: ["short", "medium"],
        tools: ["comb", "spray", "clips"],
        steps: [
          ["Wet the comb a little.", "Molhe um pouquinho o pente."],
          ["Draw a straight part from the forehead back.", "Faça uma risca reta da testa para trás."],
          ["Sweep the bigger side across your forehead.", "Jogue o lado maior sobre a testa."],
          ["Pin the smaller side behind your ear.", "Prenda o lado menor atrás da orelha."]
        ],
        tip: ["A wet comb makes a much sharper line.", "Pente molhado faz a risca ficar bem reta."] })
  ];

  /* Fill defaults on every look */
  const BASE_LOOK = {
    length: null, texture: null, updo: "none", braid: "none", tail: "plain",
    bangs: "none", accessory: "none", accColor: "pink"
  };
  STYLES.forEach(function (s) {
    s.look = Object.assign({}, BASE_LOOK, s.look);
    s.tex = s.tex || ["straight", "wavy", "curly", "coily"];
    s.len = s.len || ["short", "medium", "long"];
    s.tags = s.tags || ["everyday"];
  });

  const STYLE_BY_ID = {};
  STYLES.forEach(function (s) { STYLE_BY_ID[s.id] = s; });

  /* ---------------------------------------------------------- special days */
  function easterSunday(year) {
    /* Anonymous Gregorian algorithm */
    const a = year % 19, b = Math.floor(year / 100), c = year % 100;
    const d = Math.floor(b / 4), e = b % 4, f = Math.floor((b + 8) / 25);
    const g = Math.floor((b - f + 1) / 3);
    const h = (19 * a + b - d - g + 15) % 30;
    const i = Math.floor(c / 4), k = c % 4;
    const l = (32 + 2 * e + 2 * i - h - k) % 7;
    const m = Math.floor((a + 11 * h + 22 * l) / 451);
    const month = Math.floor((h + l - 7 * m + 114) / 31);
    const day = ((h + l - 7 * m + 114) % 31) + 1;
    return new Date(Date.UTC(year, month - 1, day));
  }

  function iso(d) {
    return d.getUTCFullYear() + "-" +
      String(d.getUTCMonth() + 1).padStart(2, "0") + "-" +
      String(d.getUTCDate()).padStart(2, "0");
  }
  function addDays(d, n) {
    return new Date(d.getTime() + n * 86400000);
  }
  function nthWeekdayOf(year, month, weekday, n) {
    const first = new Date(Date.UTC(year, month, 1));
    let offset = (weekday - first.getUTCDay() + 7) % 7;
    return new Date(Date.UTC(year, month, 1 + offset + (n - 1) * 7));
  }

  /* Each special day: emoji, name, and the hairstyle tags it calls for */
  function specialDaysFor(year, profile) {
    const map = {};
    const put = function (date, key, emoji, en, pt, tags, styles) {
      const k = typeof date === "string" ? year + "-" + date : iso(date);
      map[k] = { key: key, emoji: emoji, n: { en: en, pt: pt }, tags: tags || [], styles: styles || [] };
    };

    const easter = easterSunday(year);
    const carnivalTue = addDays(easter, -47);

    put("01-01", "newyear", "🎆", "New Year's Day", "Ano Novo", ["newyear", "fancy"], ["newyear-sparkle"]);
    put("02-14", "valentine", "💘", "Valentine's Day", "Dia de São Valentim", ["valentine"], ["heart-braid"]);
    put(addDays(carnivalTue, -3), "carnival", "🎭", "Carnival Friday", "Sexta de Carnaval", ["carnival", "party"]);
    put(addDays(carnivalTue, -2), "carnival", "🎭", "Carnival Saturday", "Sábado de Carnaval", ["carnival", "party"]);
    put(addDays(carnivalTue, -1), "carnival", "🎭", "Carnival Sunday", "Domingo de Carnaval", ["carnival", "party"]);
    put(carnivalTue, "carnival", "🎉", "Carnival Tuesday!", "Terça de Carnaval!", ["carnival", "party"], ["carnival-glitter", "feather-crown"]);
    put(addDays(carnivalTue, 1), "carnival", "😴", "Ash Wednesday", "Quarta-feira de Cinzas", ["lazy", "cozy"]);
    put(addDays(easter, -2), "easter", "✝️", "Good Friday", "Sexta-feira Santa", ["cozy", "fancy"]);
    put(easter, "easter", "🐣", "Easter Sunday", "Domingo de Páscoa", ["party", "spring"], ["space-buns"]);
    put("04-21", "tiradentes", "🇧🇷", "Tiradentes", "Tiradentes", ["brazil", "play"]);
    put("04-22", "brazil", "⛵", "Discovery of Brazil", "Descobrimento do Brasil", ["brazil", "beach"]);
    put("05-01", "labour", "🛠️", "Labour Day", "Dia do Trabalho", ["lazy", "play"]);
    put(nthWeekdayOf(year, 4, 0, 2), "mothers", "💐", "Mother's Day", "Dia das Mães", ["fancy", "party"], ["flower-crown"]);
    put("06-12", "namorados", "❤️", "Dia dos Namorados", "Dia dos Namorados", ["valentine"], ["heart-braid"]);
    put("06-13", "junina", "🎪", "Santo Antônio", "Santo Antônio", ["junina", "festival"]);
    put("06-24", "junina", "🌽", "Festa de São João", "Festa de São João", ["junina", "festival"], ["junina-braids"]);
    put("06-29", "junina", "🔥", "São Pedro", "São Pedro", ["junina", "festival"]);
    put(nthWeekdayOf(year, 7, 0, 2), "fathers", "👔", "Father's Day", "Dia dos Pais", ["fancy", "play"]);
    put("09-07", "independence", "🇧🇷", "Independence Day", "Independência do Brasil", ["brazil"], ["brazil-ribbons"]);
    put("10-12", "children", "🎈", "Children's Day", "Dia das Crianças", ["play", "party", "birthday"]);
    put("10-31", "halloween", "🎃", "Halloween", "Halloween", ["halloween"], ["spider-bun"]);
    put("11-02", "finados", "🕯️", "Finados", "Finados", ["cozy"]);
    put("11-15", "republic", "🇧🇷", "Republic Day", "Proclamação da República", ["brazil"]);
    put("11-20", "consciencia", "✊🏿", "Black Awareness Day", "Dia da Consciência Negra", ["party", "everyday"], ["afro-out", "bantu-knots"]);
    put("12-24", "christmas", "🎄", "Christmas Eve", "Véspera de Natal", ["christmas", "party"], ["christmas-braids"]);
    put("12-25", "christmas", "🎁", "Christmas Day", "Natal", ["christmas", "party"], ["christmas-braids"]);
    put("12-31", "newyear", "✨", "New Year's Eve", "Réveillon", ["newyear", "fancy"], ["newyear-sparkle"]);

    /* Season openers depend on the hemisphere */
    const south = !profile || profile.hemisphere !== "north";
    const seasonDays = south
      ? [["12-21", "summer", "☀️", "First day of summer", "Começo do verão", ["beach", "summer"]],
         ["03-20", "autumn", "🍂", "First day of autumn", "Começo do outono", ["cozy", "everyday"]],
         ["06-21", "winter", "❄️", "First day of winter", "Começo do inverno", ["cozy", "winter"]],
         ["09-22", "spring", "🌸", "First day of spring", "Começo da primavera", ["spring", "party"]]]
      : [["06-21", "summer", "☀️", "First day of summer", "Começo do verão", ["beach", "summer"]],
         ["09-22", "autumn", "🍂", "First day of autumn", "Começo do outono", ["cozy", "everyday"]],
         ["12-21", "winter", "❄️", "First day of winter", "Começo do inverno", ["cozy", "winter"]],
         ["03-20", "spring", "🌸", "First day of spring", "Começo da primavera", ["spring", "party"]]];
    seasonDays.forEach(function (s) {
      if (!map[year + "-" + s[0]]) put(s[0], s[1], s[2], s[3], s[4], s[5]);
    });

    /* Personal days always win */
    if (profile) {
      if (profile.birthday) {
        map[year + "-" + profile.birthday] = {
          key: "birthday", emoji: "🎂",
          n: { en: "Your birthday!", pt: "Seu aniversário!" },
          tags: ["birthday", "party"], styles: ["birthday-crown"]
        };
      }
      (profile.customDays || []).forEach(function (c) {
        map[year + "-" + c.md] = {
          key: "custom", emoji: c.emoji || "⭐",
          n: { en: c.name, pt: c.name },
          tags: c.tags && c.tags.length ? c.tags : ["party", "fancy"], styles: []
        };
      });
    }
    return map;
  }

  const SEASON_INFO = {
    summer: { emoji: "☀️", en: "Summer", pt: "Verão", tags: ["beach", "summer", "play"] },
    autumn: { emoji: "🍂", en: "Autumn", pt: "Outono", tags: ["everyday", "cozy", "school"] },
    winter: { emoji: "❄️", en: "Winter", pt: "Inverno", tags: ["cozy", "winter", "school"] },
    spring: { emoji: "🌸", en: "Spring", pt: "Primavera", tags: ["spring", "play", "party"] }
  };

  function seasonOf(date, hemisphere) {
    const m = date.getUTCMonth() + 1, d = date.getUTCDate();
    const n = m * 100 + d;
    let s;
    if (n >= 1221 || n < 320) s = "summer";
    else if (n < 621) s = "autumn";
    else if (n < 922) s = "winter";
    else s = "spring";
    if (hemisphere === "north") {
      s = { summer: "winter", winter: "summer", autumn: "spring", spring: "autumn" }[s];
    }
    return s;
  }

  const WEEKDAY_MOOD = [
    { en: "Sunday", pt: "Domingo", tags: ["lazy", "cozy", "play"] },
    { en: "Monday", pt: "Segunda", tags: ["school", "everyday"] },
    { en: "Tuesday", pt: "Terça", tags: ["school", "sporty"] },
    { en: "Wednesday", pt: "Quarta", tags: ["school", "everyday"] },
    { en: "Thursday", pt: "Quinta", tags: ["school", "play"] },
    { en: "Friday", pt: "Sexta", tags: ["party", "play", "school"] },
    { en: "Saturday", pt: "Sábado", tags: ["play", "party", "beach"] }
  ];

  const MONTHS = {
    en: ["January", "February", "March", "April", "May", "June", "July",
         "August", "September", "October", "November", "December"],
    pt: ["Janeiro", "Fevereiro", "Março", "Abril", "Maio", "Junho", "Julho",
         "Agosto", "Setembro", "Outubro", "Novembro", "Dezembro"]
  };
  const DOW_SHORT = {
    en: ["S", "M", "T", "W", "T", "F", "S"],
    pt: ["D", "S", "T", "Q", "Q", "S", "S"]
  };

  global.HairData = {
    HAIR_COLORS: HAIR_COLORS,
    SKIN_TONES: SKIN_TONES,
    ACC_COLORS: ACC_COLORS,
    UI: UI,
    OPT_LABELS: OPT_LABELS,
    TOOLS: TOOLS,
    STYLES: STYLES,
    STYLE_BY_ID: STYLE_BY_ID,
    specialDaysFor: specialDaysFor,
    seasonOf: seasonOf,
    SEASON_INFO: SEASON_INFO,
    WEEKDAY_MOOD: WEEKDAY_MOOD,
    MONTHS: MONTHS,
    DOW_SHORT: DOW_SHORT,
    iso: iso,
    addDays: addDays,
    easterSunday: easterSunday
  };
})(window);
