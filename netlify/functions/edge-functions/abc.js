const handler = async (request, context) => {
  const res = await context.next()
  const txt = await res.text()
  console.log(txt)
  return res
}

export default handler