#if defined(LIST_NAME)

#ifndef LIST_SCOPE
#define LIST_SCOPE static
#endif

static struct {
	LIST_NAME(Item) * header;
	LIST_NAME(Item) ** tailer;
} LIST_NAME(dlinked) = {0, &LIST_NAME(dlinked).header};

LIST_SCOPE BOOL LIST_NAME(Empty)(void)
{
	return LIST_NAME(dlinked).header == NULL;
}

LIST_SCOPE LIST_NAME(Item) * LIST_NAME(Header)(void)
{
	return LIST_NAME(dlinked).header;
}

LIST_SCOPE void LIST_NAME(Init)(LIST_NAME(Item) * item)
{
	item->magic = 0x19821131;
	item->state = 0;
	item->next = 0;
	item->prev = 0;
}

LIST_SCOPE void LIST_NAME(Insert)(LIST_NAME(Item) * item) 
{
	DS_ASSERT(item->magic == 0x19821131);

	if (item->state & AF_PENDING)
		return;
	
	item->prev = LIST_NAME(dlinked).tailer;
	item->next = NULL;

	*LIST_NAME(dlinked).tailer = item;
	LIST_NAME(dlinked).tailer = &item->next;
	item->state |= AF_PENDING;
}

LIST_SCOPE void LIST_NAME(Delete)(LIST_NAME(Item) * item)
{ 
	DS_ASSERT(item->magic == 0x19821131);

	if (item->state & AF_PENDING) {
		item->state &= ~AF_PENDING;

		*item->prev = item->next;
		if (item->next != NULL)
			item->next->prev = item->prev;

		if (LIST_NAME(dlinked).tailer == &item->next)
			LIST_NAME(dlinked).tailer = item->prev;

		item->prev = 0;
		item->next = 0;
	}
}

LIST_SCOPE void LIST_NAME(Drop)(LIST_NAME(Item) * item)
{
   	DS_ASSERT(item->magic == 0x19821131);
	if (item->state & AF_PENDING)
		LIST_NAME(Delete)(item);
	item->magic = 0;
}

#endif
