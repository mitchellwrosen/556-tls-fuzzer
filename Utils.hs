{-# LANGUAGE ScopedTypeVariables #-}

module Utils where

import Control.Concurrent.ParallelIO.Local (withPool, parallel)
import Control.Exception
import Debug.Trace

tracem :: Monad m => String -> m ()
tracem = flip trace (return ())

forMn_ :: Monad m => [a] -> (a -> Int -> m b) -> m ()
forMn_ = go 0
  where
    go _ []     _ = return ()
    go n (x:xs) f = f x n >> go (n+1) xs f

-- | Run an action to completion. If it throws an exception, run the second
-- action to completion.
catch' :: IO a -> IO a -> IO a
catch' a b = a `catch` (\(_ :: SomeException) -> b)

-- | Run the IO actions in parallel with the provided number of threads.
parallelWithPoolOf :: Int -> [IO a] -> IO [a]
parallelWithPoolOf n as = withPool n (\pool -> parallel pool as)
