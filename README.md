# AshAi

This is a _HIGHLY EXPERIMENTAL_ package. It is 500 lines of code built for a demo.

## What is it?

This is a chat interface for your Ash app. It can call actions on your resources
to fulfill requests. It will always honor your policy rules on your application, and
an actor can be provided, whereby all actions will be taken on their behalf.

The bot may very well do things you "don't want it to do", but it cannot perform
any kind of privelege escalation because it always operates by calling actions on
resources, never by accessing data directly.

## What goes into making this ready?

1. Must be made agnostic to provider.
   Right now it works directly with Open AI, using an environment variable.
2. There are limits to the amount of functions that can be provided when chatting
   if there are too many resources/actions, we need to group them and allow the chat
   bot to ask to expand on groups of functions (via a tool).
3. Some easier to do the chat on a loop where the interface is something like a chat window
   in liveview.
4. Some kind of management of how much of the context window we are using. How much chat history,
   how big the functions are.
5. A string format for filters (maybe) so we can give it a format instead of a massive json schema
   of filters.
6. Customization of the initial system prompt.
7. At _least_ one test should be written :D

## What else ought to happen?

1. more action types, like bulk updates, bulk destroys, bulk creates.

## Installation

This is not yet available on hex.

```elixir
def deps do
  [
    {:ash_ai, github: "ash-project/ash_ai"}
  ]
end
```

## How to play with it

1. Set the environment variable `OPENAI_API_KEY` to your Open AI API key.
2. Run `iex -S mix` and then run `AshAi.iex_chat` to start chatting with your app.
3. To build your own chat interface, you'll use `AshAi.instruct/2`. See the implementation
   of `AshAi.iex_chat` to see how its done.

### Example

```elixir
AshAi.iex_chat(actor: user, actions: [{Twitter.Tweets.Tweet, :*}])
```
