(function(){
  var out=[];
  out.push("IFCDN="+String(window.IFCDN).slice(0,1200));
  // probe whether a TO_IFC_EXT transport listens on window: send a benign version cmd and see if anything replies
  out.push("hasIFCHash="+typeof window.IFCHash);
  out.push("hasIFCConst.emptyString="+ (window.IFCConst&&typeof window.IFCConst.emptyString));
  return out.join("\n");
})();
